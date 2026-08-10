#import <Foundation/Foundation.h>
#import <sys/time.h>
#import <CoreFoundation/CoreFoundation.h>
#import "fishhook.h" // Thư viện hook hàm C hỗ trợ non-jailbreak rất tốt

// Hệ số nhân tốc độ (Ví dụ: x5.0)
static float speed_factor = 5.0f;

// Lưu trữ con trỏ hàm gốc
static int (*orig_gettimeofday)(struct timeval *tv, struct timezone *tz);
static CFAbsoluteTime (*orig_CFAbsoluteTimeGetCurrent)(void);

// Biến tính toán thời gian giả lập
static struct timeval last_real_tv;
static struct timeval fake_tv;
static CFAbsoluteTime last_real_cf = 0;
static CFAbsoluteTime fake_cf = 0;

// 1. Hook hàm gettimeofday
int my_gettimeofday(struct timeval *tv, struct timezone *tz) {
    int ret = orig_gettimeofday(tv, tz);
    if (ret != 0 || tv == NULL) return ret;

    if (last_real_tv.tv_sec == 0) {
        last_real_tv = *tv;
        fake_tv = *tv;
    } else {
        // Tính khoảng thời gian thực vừa trôi qua
        double delta = (tv->tv_sec - last_real_tv.tv_sec) + 
                       (tv->tv_usec - last_real_tv.tv_usec) / 1000000.0;
        
        // Nhân với hệ số speed
        double fake_delta = delta * speed_factor;
        
        // Cập nhật thời gian giả
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

// 2. Hook hàm CFAbsoluteTimeGetCurrent
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

// Khởi tạo Hook khi Dylib được load vào App
__attribute__((constructor))
static void initialize() {
    // Dùng fishhook để rebind symbol
    rebind_symbols((struct rebinding[2]){
        {"gettimeofday", my_gettimeofday, (void *)&orig_gettimeofday},
        {"CFAbsoluteTimeGetCurrent", my_CFAbsoluteTimeGetCurrent, (void *)&orig_CFAbsoluteTimeGetCurrent}
    }, 2);
}
