#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

// ============================================================================
// INTERFACE (Khai báo Class và các Phương thức)
// ============================================================================
@interface MyLibrary : NSObject

+ (instancetype)sharedManager;
- (void)postNewOrderEvent:(NSDictionary *)orderInfo;
- (void)listenForOrdersInViewController:(UIViewController *)viewController;

@end

// ============================================================================
// IMPLEMENTATION (Thực thi chi tiết)
// ============================================================================
@implementation MyLibrary

// Singleton Pattern để dùng chung 1 instance trong ứng dụng
+ (instancetype)sharedManager {
    static MyLibrary *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[MyLibrary alloc] init];
    });
    return shared;
}

// Hàm phát sự kiện đơn hàng mới
- (void)postNewOrderEvent:(NSDictionary *)orderInfo {
    if (!orderInfo) return;
    
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] postNotificationName:@"AppDidReceiveNewOrderNotification"
                                                            object:nil
                                                          userInfo:orderInfo];
    });
}

// Hàm đăng ký lắng nghe và hiển thị Alert thông báo lên màn hình
- (void)listenForOrdersInViewController:(UIViewController *)viewController {
    if (!viewController) return;

    [[NSNotificationCenter defaultCenter] addObserverForName:@"AppDidReceiveNewOrderNotification"
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification * _Nonnull note) {
        NSDictionary *orderData = note.userInfo;
        NSString *orderId = orderData[@"id"] ? [NSString stringWithFormat:@"%@", orderData[@"id"]] : @"Mới";
        NSString *message = [NSString stringWithFormat:@"Đã nhận đơn hàng số: %@", orderId];
        
        // Hiển thị Alert trên UI
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Thông Báo Đơn Hàng"
                                                                       message:message
                                                                preferredStyle:UIAlertControllerStyleAlert];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleDefault handler:nil]];
        
        [viewController presentViewController:alert animated:YES completion:nil];
    }];
}

@end
