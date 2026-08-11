#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <sys/time.h>
#import <CoreFoundation/CoreFoundation.h>
#import <objc/runtime.h>
#import <mach/mach_time.h>
#import <dlfcn.h>
#import <stdlib.h>
#import <string.h>
#import <sys/types.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>

#ifndef LC_SEGMENT_ARCH_DEPENDENT
#ifdef __LP64__
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif
#endif

// ==========================================
// 1. EMBEDDED FISHHOOK IMPLEMENTATION
// ==========================================
#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct load_command load_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct load_command load_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST "__DATA_CONST"
#endif

struct rebinding {
  const char *name;
  void *replacement;
  void **replaced;
};

struct rebindings_entry {
  struct rebinding *rebindings;
  size_t rebindings_nel;
  struct rebindings_entry *next;
};

static struct rebindings_entry *_rebindings_head = NULL;

static int perform_rebinding_with_section(struct rebindings_entry *rebindings,
                                          section_t *section,
                                          intptr_t slide,
                                          nlist_t *symtab,
                                          char *strtab,
                                          uint32_t *indirect_symtab) {
  uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
  void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
  for (uint32_t i = 0; i < section->size / sizeof(void *); i++) {
    uint32_t symtab_index = indirect_symbol_indices[i];
    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
        symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
      continue;
    }
    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
    char *symbol_name = strtab + strtab_offset;
    bool symbol_has_leading_underscore = symbol_name[0] == '_';
    struct rebindings_entry *cur = rebindings;
    while (cur) {
      for (uint32_t j = 0; j < cur->rebindings_nel; j++) {
        uint32_t symbol_name_offset = symbol_has_leading_underscore ? 1 : 0;
        if (strcmp(&symbol_name[symbol_name_offset], cur->rebindings[j].name) == 0) {
          if (cur->rebindings[j].replaced != NULL &&
              indirect_symbol_bindings[i] != cur->rebindings[j].replacement) {
            *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
          }
          indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
          goto symbol_loop;
        }
      }
      cur = cur->next;
    }
  symbol_loop:;
  }
  return 0;
}

static void rebind_symbols_for_image(struct rebindings_entry *rebindings,
                                     const struct mach_header *header,
                                     intptr_t slide) {
  Dl_info info;
  if (dladdr(header, &info) == 0) return;

  segment_command_t *cur_seg_cmd;
  segment_command_t *linkedit_segment = NULL;
  struct symtab_command* symtab_cmd = NULL;
  struct dysymtab_command* dysymtab_cmd = NULL;

  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint32_t i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
        linkedit_segment = cur_seg_cmd;
      }
    } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
      symtab_cmd = (struct symtab_command*)cur_seg_cmd;
    } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
      dysymtab_cmd = (struct dysymtab_command*)cur_seg_cmd;
    }
  }

  if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment) return;

  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
  nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
  char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
  uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

  cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint32_t i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
          strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0) {
        continue;
      }
      for (uint32_t j = 0; j < cur_seg_cmd->nsects; j++) {
        section_t *sect = (section_t *)(cur + sizeof(segment_command_t)) + j;
        if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS ||
            (sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
          perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
        }
      }
    }
  }
}

static void _rebind_symbols_for_image(const struct mach_header *header, intptr_t slide) {
    rebind_symbols_for_image(_rebindings_head, header, slide);
}

static int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
  struct rebindings_entry *new_entry = (struct rebindings_entry *)malloc(sizeof(struct rebindings_entry));
  if (!new_entry) return -1;
  new_entry->rebindings = (struct rebinding *)malloc(sizeof(struct rebinding) * rebindings_nel);
  if (!new_entry->rebindings) {
    free(new_entry);
    return -1;
  }
  memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * rebindings_nel);
  new_entry->rebindings_nel = rebindings_nel;
  new_entry->next = _rebindings_head;
  _rebindings_head = new_entry;
  
  if (!_rebindings_head->next) {
    _dyld_register_func_for_add_image(_rebind_symbols_for_image);
  } else {
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
      rebind_symbols_for_image(new_entry, _dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    }
  }
  return 0;
}

// ==========================================
// 2. SPEED CONTROL STATE
// ==========================================
static float speed_factor = 2.0f; // Hệ số tốc độ mặc định

static int (*orig_gettimeofday)(struct timeval *tv, struct timezone *tz);
static CFAbsoluteTime (*orig_CFAbsoluteTimeGetCurrent)(void);
static uint64_t (*orig_mach_absolute_time)(void);

static struct timeval last_real_tv;
static struct timeval fake_tv;

static CFAbsoluteTime last_real_cf = 0;
static CFAbsoluteTime fake_cf = 0;

static uint64_t last_real_mach = 0;
static uint64_t fake_mach = 0;

int my_gettimeofday(struct timeval *tv, struct timezone *tz) {
    int ret = orig_gettimeofday(tv, tz);
    if (ret != 0 || tv == NULL) return ret;

    if (last_real_tv.tv_sec == 0) {
        last_real_tv = *tv;
        fake_tv = *tv;
    } else {
        double delta = (tv->tv_sec - last_real_tv.tv_sec) + 
                       (tv->tv_usec - last_real_tv.tv_usec) / 1000000.0;
        double fake_delta = delta * speed_factor;
        
        long sec_add = (long)fake_delta;
        long usec_add = (long)((fake_delta - sec_add) * 1000000.0);
        
        fake_tv.tv_sec += sec_add;
        fake_tv.tv_usec += usec_add;
        if (fake_tv.tv_usec >= 1000000) {
            fake_tv.tv_sec += 1;
            fake_tv.tv_usec -= 1000000;
        }
        last_real_tv = *tv;
    }

    *tv = fake_tv;
    return ret;
}

CFAbsoluteTime my_CFAbsoluteTimeGetCurrent(void) {
    CFAbsoluteTime real_now = orig_CFAbsoluteTimeGetCurrent();
    if (last_real_cf == 0) {
        last_real_cf = real_now;
        fake_cf = real_now;
    } else {
        double delta = real_now - last_real_cf;
        fake_cf += delta * speed_factor;
        last_real_cf = real_now;
    }
    return fake_cf;
}

uint64_t my_mach_absolute_time(void) {
    uint64_t real_now = orig_mach_absolute_time();
    if (last_real_mach == 0) {
        last_real_mach = real_now;
        fake_mach = real_now;
    } else {
        uint64_t delta = real_now - last_real_mach;
        fake_mach += (uint64_t)(delta * speed_factor);
        last_real_mach = real_now;
    }
    return fake_mach;
}

static void swizzle_NSDate_methods(void) {
    Class nsdateClass = [NSDate class];
    Method origRefMethod = class_getClassMethod(nsdateClass, @selector(timeIntervalSinceReferenceDate));
    if (origRefMethod) {
        method_setImplementation(origRefMethod, (IMP)my_CFAbsoluteTimeGetCurrent);
    }
    Method origDateMethod = class_getClassMethod(nsdateClass, @selector(date));
    if (origDateMethod) {
        IMP newDateImp = imp_implementationWithBlock(^id(id self) {
            return [NSDate dateWithTimeIntervalSinceReferenceDate:my_CFAbsoluteTimeGetCurrent()];
        });
        method_setImplementation(origDateMethod, newDateImp);
    }
}

// ==========================================
// 3. PASSTHROUGH OVERLAY WINDOW
// ==========================================
@interface SpeedhackPassthroughWindow : UIWindow
@property (nonatomic, weak) UIView *gearButton;
@property (nonatomic, weak) UIView *menuView;
@end

@implementation SpeedhackPassthroughWindow

- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    if (self.gearButton && !self.gearButton.hidden) {
        CGPoint buttonPoint = [self.gearButton convertPoint:point fromView:self];
        if ([self.gearButton pointInside:buttonPoint withEvent:event]) {
            return [super hitTest:point withEvent:event];
        }
    }
    
    if (self.menuView && !self.menuView.hidden) {
        CGPoint menuPoint = [self.menuView convertPoint:point fromView:self];
        if ([self.menuView pointInside:menuPoint withEvent:event]) {
            return [super hitTest:point withEvent:event];
        }
    }
    
    return nil;
}

@end

// ==========================================
// 4. OVERLAY UI MANAGEMENT
// ==========================================
@interface SpeedhackUI : NSObject
@property (nonatomic, strong) SpeedhackPassthroughWindow *overlayWindow;
@property (nonatomic, strong) UIButton *gearButton;
@property (nonatomic, strong) UIView *menuView;
@property (nonatomic, strong) UILabel *speedLabel;
@property (nonatomic, strong) UISlider *speedSlider;
@property (nonatomic, strong) NSTimer *idleTimer;
+ (instancetype)sharedInstance;
- (void)setupUI;
@end

@implementation SpeedhackUI

+ (instancetype)sharedInstance {
    static SpeedhackUI *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[SpeedhackUI alloc] init];
    });
    return instance;
}

- (void)setupUI {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.overlayWindow) return;

        CGRect screenBounds = [UIScreen mainScreen].bounds;

        self.overlayWindow = [[SpeedhackPassthroughWindow alloc] initWithFrame:screenBounds];
        self.overlayWindow.windowLevel = UIWindowLevelStatusBar + 99999;
        self.overlayWindow.backgroundColor = [UIColor clearColor];

        UIViewController *rootVC = [[UIViewController alloc] init];
        rootVC.view.backgroundColor = [UIColor clearColor];
        
        self.overlayWindow.rootViewController = rootVC;
        self.overlayWindow.hidden = NO;

        // 1. Nút Bánh xe ⚙️
        self.gearButton = [UIButton buttonWithType:UIButtonTypeCustom];
        self.gearButton.frame = CGRectMake(20, 150, 50, 50);
        self.gearButton.layer.cornerRadius = 25;
        self.gearButton.backgroundColor = [UIColor colorWithRed:0.1 green:0.1 blue:0.1 alpha:0.9];
        self.gearButton.layer.borderWidth = 2.0;
        self.gearButton.layer.borderColor = [UIColor colorWithRed:0.2 green:0.8 blue:0.4 alpha:1.0].CGColor;
        [self.gearButton setTitle:@"⚙️" forState:UIControlStateNormal];
        self.gearButton.titleLabel.font = [UIFont systemFontOfSize:28];
        self.gearButton.clipsToBounds = YES;

        UIPanGestureRecognizer *panGesture = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
        [self.gearButton addGestureRecognizer:panGesture];
        [self.gearButton addTarget:self action:@selector(gearButtonClicked) forControlEvents:UIControlEventTouchUpInside];
        [rootVC.view addSubview:self.gearButton];

        // 2. Menu Điều Chỉnh gọn nhẹ
        self.menuView = [[UIView alloc] initWithFrame:CGRectMake((screenBounds.size.width - 250) / 2, (screenBounds.size.height - 150) / 2, 250, 150)];
        self.menuView.backgroundColor = [UIColor colorWithRed:0.12 green:0.12 blue:0.14 alpha:0.98];
        self.menuView.layer.cornerRadius = 16;
        self.menuView.layer.borderWidth = 1.5;
        self.menuView.layer.borderColor = [UIColor colorWithRed:0.2 green:0.8 blue:0.4 alpha:0.8].CGColor;
        self.menuView.hidden = YES;

        UILabel *titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(10, 12, 230, 24)];
        titleLabel.text = @"⚡ Speedhack Menu";
        titleLabel.textColor = [UIColor whiteColor];
        titleLabel.font = [UIFont boldSystemFontOfSize:16];
        titleLabel.textAlignment = NSTextAlignmentCenter;
        [self.menuView addSubview:titleLabel];

        // Hiển thị tốc độ
        self.speedLabel = [[UILabel alloc] initWithFrame:CGRectMake(15, 45, 220, 20)];
        self.speedLabel.text = [NSString stringWithFormat:@"Hệ số tốc độ: %.1fx", speed_factor];
        self.speedLabel.textColor = [UIColor colorWithRed:0.2 green:0.8 blue:1.0 alpha:1.0];
        self.speedLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
        [self.menuView addSubview:self.speedLabel];

        // Thanh kéo tốc độ (Slider)
        self.speedSlider = [[UISlider alloc] initWithFrame:CGRectMake(15, 70, 220, 30)];
        self.speedSlider.minimumValue = 0.5f;
        self.speedSlider.maximumValue = 20.0f;
        self.speedSlider.value = speed_factor;
        self.speedSlider.tintColor = [UIColor colorWithRed:0.2 green:0.8 blue:0.4 alpha:1.0];
        [self.speedSlider addTarget:self action:@selector(sliderValueChanged:) forControlEvents:UIControlEventValueChanged];
        [self.menuView addSubview:self.speedSlider];

        // Nút Đóng Menu
        UIButton *closeButton = [UIButton buttonWithType:UIButtonTypeSystem];
        closeButton.frame = CGRectMake(15, 110, 220, 30);
        closeButton.backgroundColor = [UIColor colorWithWhite:0.25 alpha:0.8];
        closeButton.layer.cornerRadius = 8;
        [closeButton setTitle:@"Đóng Menu" forState:UIControlStateNormal];
        [closeButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        closeButton.titleLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightBold];
        [closeButton addTarget:self action:@selector(toggleMenu) forControlEvents:UIControlEventTouchUpInside];
        [self.menuView addSubview:closeButton];

        [rootVC.view addSubview:self.menuView];

        self.overlayWindow.gearButton = self.gearButton;
        self.overlayWindow.menuView = self.menuView;

        [self resetIdleTimer];
    });
}

- (void)sliderValueChanged:(UISlider *)slider {
    [self resetIdleTimer];
    speed_factor = slider.value;
    self.speedLabel.text = [NSString stringWithFormat:@"Hệ số tốc độ: %.1fx", speed_factor];
}

- (void)resetIdleTimer {
    [self.idleTimer invalidate];
    [UIView animateWithDuration:0.2 animations:^{
        self.gearButton.alpha = 1.0f;
    }];
    self.idleTimer = [NSTimer scheduledTimerWithTimeInterval:5.0
                                                      target:self
                                                    selector:@selector(fadeGearButton)
                                                    userInfo:nil
                                                     repeats:NO];
}

- (void)fadeGearButton {
    if (!self.menuView.hidden) return;
    [UIView animateWithDuration:0.5 animations:^{
        self.gearButton.alpha = 0.15f;
    }];
}

- (void)gearButtonClicked {
    [self resetIdleTimer];
    [self toggleMenu];
}

- (void)handlePan:(UIPanGestureRecognizer *)pan {
    [self resetIdleTimer];
    CGPoint translation = [pan translationInView:self.overlayWindow];
    CGPoint newCenter = CGPointMake(pan.view.center.x + translation.x, pan.view.center.y + translation.y);
    CGRect screenRect = [UIScreen mainScreen].bounds;
    newCenter.x = MIN(MAX(newCenter.x, 25), screenRect.size.width - 25);
    newCenter.y = MIN(MAX(newCenter.y, 25), screenRect.size.height - 25);
    pan.view.center = newCenter;
    [pan setTranslation:CGPointZero inView:self.overlayWindow];
}

- (void)toggleMenu {
    [self resetIdleTimer];
    self.menuView.hidden = !self.menuView.hidden;
}

@end

// ==========================================
// 5. INITIALIZER
// ==========================================
__attribute__((constructor))
static void initialize(void) {
    struct rebinding rebindings[] = {
        {"gettimeofday", (void *)my_gettimeofday, (void **)&orig_gettimeofday},
        {"CFAbsoluteTimeGetCurrent", (void *)my_CFAbsoluteTimeGetCurrent, (void **)&orig_CFAbsoluteTimeGetCurrent},
        {"mach_absolute_time", (void *)my_mach_absolute_time, (void **)&orig_mach_absolute_time}
    };
    rebind_symbols(rebindings, 3);
    swizzle_NSDate_methods();

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [[SpeedhackUI sharedInstance] setupUI];
    });

    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification * _Nonnull note) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [[SpeedhackUI sharedInstance] setupUI];
        });
    }];
}
