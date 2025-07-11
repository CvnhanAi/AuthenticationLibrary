// xztime.mm

#import "xztime.h"
#import "mahoa.h"
#import <UIKit/UIKit.h>
#import "UICKeyChainStore/UICKeyChainStore.h"
#import "FCUUID/FCUUID.h"

/// Các hằng số cấu hình (mã hoá nếu cần)


/// Tên service cho Keychain
typedef NSString xzt;
static xzt * const kServiceName = @"com.xztime";

@implementation xztime

+ (void)paid:(void (^)(void))execute {
    // Thử tự động đăng nhập bằng key đã lưu
    UICKeyChainStore *store = [UICKeyChainStore keyChainStoreWithService:kServiceName];
    NSString *savedKey = [store stringForKey:@"userKey"];
    NSString *savedEndTime = [store stringForKey:@"keyEndTime"];
    if (savedKey.length > 0 && savedEndTime.length > 0) {
        // Kiểm tra endTime
        NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
        fmt.dateFormat = @"yyyy-MM-dd HH:mm:ss"; // đảm bảo khớp format server trả về
        NSDate *expiry = [fmt dateFromString:savedEndTime];
        if ([expiry timeIntervalSinceNow] > 0) {
            // Key còn hạn, hiển thị thông báo và thực thi
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self showSuccess:[NSString stringWithFormat:@"Thời hạn sử dụng:\n%@", savedEndTime]];
                        });            

            if (execute) execute();
            return;
        } else {
            // Key hết hạn
            [self deleteStoredKey];
        }
    }
    // Nếu không có key hoặc đã xóa, hiển thị hộp thoại nhập key
    [self presentKeyInputAlertWithCompletion:execute];
}

#pragma mark - Private Methods

+ (void)fetchPackageInfoWithCompletion:(void(^)(NSDictionary *packageInfo))completion {
    NSString *urlString = [NSString stringWithFormat:@"%@api/xzxz.php?token=%@", __kBaseURL, __kHashDefaultValue];
    NSURL *url = [NSURL URLWithString:urlString];
    NSURLSession *session = [NSURLSession sharedSession];

    NSURLSessionDataTask *task = [session dataTaskWithURL:url
                                        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error) {
            NSLog(@"Error fetching data: %@", error);
            completion(nil);
            return;
        }

        NSError *jsonError = nil;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];

        if (jsonError) {
            completion(nil);
            return;
        }

        NSDictionary *packageInfo = json[@"package_info"];
        completion(packageInfo);
    }];

    [task resume];
}

+ (void)presentKeyInputAlertWithCompletion:(void(^)(void))completion {
    [self fetchPackageInfoWithCompletion:^(NSDictionary *packageInfo) {
        if (!packageInfo) {
            [self showError:@"Không thể lấy thông tin gói"];
            exit(0);
            // return;
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            UIViewController *root = UIApplication.sharedApplication.keyWindow.rootViewController;
            __block int remaining = 30;
            NSString *title = [NSString stringWithFormat:@"%@", packageInfo[@"deb_name"]];
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                           message:[NSString stringWithFormat:@"%@ \n(%02d:%02d)", __Input, remaining/60, remaining%60]
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
                tf.placeholder = __Input;
                if (UIPasteboard.generalPasteboard.string) {
                    tf.text = UIPasteboard.generalPasteboard.string;
                }
            }];

            __block NSTimer *timer = [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *t) {
                remaining--;
                alert.message = [NSString stringWithFormat:@"%@ \n(%02d:%02d)", __Input, remaining/60, remaining%60];
                if (remaining <= 0) {
                    [t invalidate];
                    [alert dismissViewControllerAnimated:YES completion:^{
                        [self deleteStoredKey];
                        [self showError:NSSENCRYPT("Hết thời gian nhập key")];
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                            exit(0);
                        });
                    }];
                }
            }];

            UIAlertAction *confirm = [UIAlertAction actionWithTitle:NSSENCRYPT("Xác nhận") style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                [timer invalidate];
                NSString *key = alert.textFields.firstObject.text;
                if (key.length == 0) {
                    [self deleteStoredKey];
                    [self showError:NSSENCRYPT("Key không được để trống")];
                    [self presentKeyInputAlertWithCompletion:completion];
                    return;
                }
                [self validateKey:key completion:^(BOOL ok, NSString *endTime) {
                    if (ok) {
                        UICKeyChainStore *store = [UICKeyChainStore keyChainStoreWithService:kServiceName];
                        [store setString:key forKey:@"userKey"];
                        if (endTime) {
                            [store setString:endTime forKey:@"keyEndTime"];
                        }
                        [self showSuccess:[NSString stringWithFormat:@"Thời hạn sử dụng: \n%@", endTime]];
                        if (completion) completion();
                    } else {
                        [self deleteStoredKey];
                        [self showError:NSSENCRYPT("Key không hợp lệ hoặc hết hạn")];
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                            [self presentKeyInputAlertWithCompletion:completion];
                        });
                    }
                }];
            }];
            [alert addAction:confirm];
            [root presentViewController:alert animated:YES completion:nil];
        });
    }];
}

+ (void)validateKey:(NSString *)key completion:(void(^)(BOOL success, NSString *endTime))completion {
    NSString *uuid = [self getDeviceUUID];
    NSString *urlStr = [NSString stringWithFormat:@"%@api/xzxz.php?key=%@&uuid=%@&token=%@", __kBaseURL, key, uuid, __kHashDefaultValue];
    NSURL *url = [NSURL URLWithString:urlStr];
    [[[NSURLSession sharedSession] dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        if (err || !data) { completion(NO, nil); return; }
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        if (![json isKindOfClass:[NSDictionary class]] || ![json[@"status"] isEqualToString:@"success"]) {
            completion(NO, nil);
        } else {
            completion(YES, json[@"key_info"][@"end_time"]);
        }
    }] resume];
}

+ (NSString *)getDeviceUUID {
    UICKeyChainStore *store = [UICKeyChainStore keyChainStoreWithService:kServiceName];
    NSString *uuid = [store stringForKey:@"deviceUUID"];
    if (uuid.length == 0) {
        uuid = [FCUUID uuidForDevice];
        [store setString:uuid forKey:@"deviceUUID"];
    }
    return uuid;
}

+ (void)deleteStoredKey {
    UICKeyChainStore *store = [UICKeyChainStore keyChainStoreWithService:kServiceName];
    [store removeItemForKey:@"userKey"];
    [store removeItemForKey:@"keyEndTime"];
}

+ (void)showError:(NSString *)msg {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController *root = UIApplication.sharedApplication.keyWindow.rootViewController;
        UIAlertController *err = [UIAlertController alertControllerWithTitle:nil message:msg preferredStyle:UIAlertControllerStyleAlert];
        [root presentViewController:err animated:YES completion:^{
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                [err dismissViewControllerAnimated:YES completion:nil];
            });
        }];
    });
}

+ (void)showSuccess:(NSString *)msg{
    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController *root = UIApplication.sharedApplication.keyWindow.rootViewController;
        UIAlertController *suc = [UIAlertController alertControllerWithTitle:@"Đăng Nhập Thành Công" message:msg preferredStyle:UIAlertControllerStyleAlert];
        [root presentViewController:suc animated:YES completion:^{
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                [suc dismissViewControllerAnimated:YES completion:nil];
            });
        }];
    });
}

@end