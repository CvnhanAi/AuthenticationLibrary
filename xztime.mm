// xztime.mm

#import "xztime.h"
#import "mahoa.h"
#import <UIKit/UIKit.h>
#import "UICKeyChainStore/UICKeyChainStore.h"
#import "FCUUID/FCUUID.h"
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>
#import <sys/stat.h>
#import <sys/ptrace.h>

#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

/// Các hằng số cấu hình (mã hoá nếu cần)

/// Security Constants
static const char *kJailbreakPaths[] = {
    "/Applications/Cydia.app",
    "/Applications/blackra1n.app", 
    "/Applications/FakeCarrier.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSettings.app",
    "/Applications/WinterBoard.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
    "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/mobile/Library/SBSettings/Themes",
    "/private/var/tmp/cydia.log",
    "/private/var/stash",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/usr/bin/sshd",
    "/usr/libexec/sftp-server",
    "/usr/sbin/sshd",
    "/etc/apt",
    "/bin/bash",
    "/usr/bin/ssh"
};

static const int kJailbreakPathsCount = sizeof(kJailbreakPaths) / sizeof(kJailbreakPaths[0]);

/// Tên service cho Keychain
typedef NSString xzt;
static xzt * const kServiceName = @"com.xztime";

@implementation xztime

+ (void)paid:(void (^)(void))execute {
    // Perform security checks first
    [self performIntegrityCheck];
    
    // Thử tự động đăng nhập bằng key đã lưu
    UICKeyChainStore *store = [self getSecureKeychain];
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
            [self secureDeleteStoredKey];
        }
    }
    // Nếu không có key hoặc đã xóa, hiển thị hộp thoại nhập key
    [self presentKeyInputAlertWithCompletion:execute];
}

#pragma mark - Private Methods

+ (void)fetchPackageInfoWithCompletion:(void(^)(NSDictionary *packageInfo))completion {
    NSString *urlString = [NSString stringWithFormat:@"%@api/xzxz.php", __kBaseURL];
    
    NSDictionary *params = @{
        @"token": __kHashDefaultValue
    };
    
    [self makeSecureRequest:urlString params:params completion:^(BOOL success, NSDictionary *response) {
        if (!success || !response) {
            completion(nil);
            return;
        }
        
        NSDictionary *packageInfo = response[@"package_info"];
        completion(packageInfo);
    }];
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
                        [self secureDeleteStoredKey];
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
                    [self secureDeleteStoredKey];
                    [self showError:NSSENCRYPT("Key không được để trống")];
                    [self presentKeyInputAlertWithCompletion:completion];
                    return;
                }
                [self validateKey:key completion:^(BOOL ok, NSString *endTime) {
                    if (ok) {
                        UICKeyChainStore *store = [self getSecureKeychain];
                        [store setString:key forKey:@"userKey"];
                        if (endTime) {
                            [store setString:endTime forKey:@"keyEndTime"];
                        }
                        [self showSuccess:[NSString stringWithFormat:@"Thời hạn sử dụng: \n%@", endTime]];
                        if (completion) completion();
                    } else {
                        [self secureDeleteStoredKey];
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
    NSString *urlStr = [NSString stringWithFormat:@"%@api/xzxz.php", __kBaseURL];
    
    NSDictionary *params = @{
        @"key": key,
        @"uuid": uuid,
        @"token": __kHashDefaultValue
    };
    
    [self makeSecureRequest:urlStr params:params completion:^(BOOL success, NSDictionary *response) {
        if (!success || !response) {
            completion(NO, nil);
            return;
        }
        
        if (![response[@"status"] isEqualToString:@"success"]) {
            completion(NO, nil);
        } else {
            completion(YES, response[@"key_info"][@"end_time"]);
        }
    }];
}

+ (NSString *)getDeviceUUID {
    UICKeyChainStore *store = [self getSecureKeychain];
    NSString *uuid = [store stringForKey:@"deviceUUID"];
    if (uuid.length == 0) {
        uuid = [FCUUID uuidForDevice];
        [store setString:uuid forKey:@"deviceUUID"];
    }
    return uuid;
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

#pragma mark - Security Enhancement Methods

+ (BOOL)isDeviceCompromised {
    // Check for jailbreak files
    for (int i = 0; i < kJailbreakPathsCount; i++) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:[NSString stringWithUTF8String:kJailbreakPaths[i]]]) {
            return YES;
        }
    }
    
    // Check if we can write to system directory
    NSString *testPath = NSSENCRYPT("/private/jailbreak.txt");
    NSError *error;
    [@"test" writeToFile:testPath atomically:YES encoding:NSUTF8StringEncoding error:&error];
    if (!error) {
        [[NSFileManager defaultManager] removeItemAtPath:testPath error:nil];
        return YES;
    }
    
    // Check for common jailbreak tools
    if (system(NULL)) {
        return YES;
    }
    
    // Check dyld library loading
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && (strstr(name, "MobileSubstrate") || strstr(name, "cycript") || strstr(name, "substrate"))) {
            return YES;
        }
    }
    
    return NO;
}

+ (BOOL)verifyApplicationIntegrity {
    // Basic binary integrity check using stat
    struct stat stat_buf;
    const char *appPath = [[[NSBundle mainBundle] executablePath] UTF8String];
    if (stat(appPath, &stat_buf) != 0) {
        return NO;
    }
    
    // Check modification time (basic check)
    time_t currentTime = time(NULL);
    if (difftime(currentTime, stat_buf.st_mtime) > 86400) { // More than a day old
        // This is a very basic check - in production you'd want more sophisticated verification
    }
    
    return YES;
}

+ (void)enableAntiDebugging {
    // Basic anti-debugging using ptrace
    #ifdef DEBUG
    // Skip in debug builds
    return;
    #endif
    
    // Simple ptrace check
    if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
        // Debugger detected, exit
        exit(0);
    }
}

+ (void)setupSSLPinning:(NSURLSessionConfiguration *)config {
    // Note: Full SSL pinning implementation would require certificate data
    // This sets up basic secure configuration
    config.TLSMinimumSupportedProtocol = kTLSProtocol12;
    config.TLSMaximumSupportedProtocol = kTLSProtocol13;
    config.timeoutIntervalForRequest = 30.0;
    config.timeoutIntervalForResource = 60.0;
}

+ (NSString *)createRequestSignature:(NSDictionary *)params {
    // Create HMAC-SHA256 signature
    NSMutableString *queryString = [NSMutableString string];
    NSArray *sortedKeys = [[params allKeys] sortedArrayUsingSelector:@selector(compare:)];
    
    for (NSString *key in sortedKeys) {
        if (queryString.length > 0) {
            [queryString appendString:@"&"];
        }
        [queryString appendFormat:@"%@=%@", key, params[key]];
    }
    
    const char *keyBytes = [__kHashDefaultValue UTF8String];
    const char *dataBytes = [queryString UTF8String];
    
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, keyBytes, strlen(keyBytes), dataBytes, strlen(dataBytes), result);
    
    NSMutableString *signature = [NSMutableString string];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [signature appendFormat:@"%02x", result[i]];
    }
    
    return [signature copy];
}

+ (void)makeSecureRequest:(NSString *)url params:(NSDictionary *)params completion:(void(^)(BOOL success, NSDictionary *response))completion {
    // Add timestamp and signature
    NSMutableDictionary *secureParams = [params mutableCopy] ?: [NSMutableDictionary dictionary];
    secureParams[@"timestamp"] = @([[NSDate date] timeIntervalSince1970]);
    secureParams[@"device_id"] = [self getDeviceUUID];
    
    NSString *signature = [self createRequestSignature:secureParams];
    secureParams[@"signature"] = signature;
    
    // Create secure URL session
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
    [self setupSSLPinning:config];
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config];
    
    // Build URL with params
    NSMutableString *urlString = [url mutableCopy];
    BOOL first = ![url containsString:@"?"];
    
    for (NSString *key in secureParams) {
        [urlString appendFormat:@"%@%@=%@", first ? @"?" : @"&", key, secureParams[key]];
        first = NO;
    }
    
    NSURL *requestURL = [NSURL URLWithString:urlString];
    
    NSURLSessionDataTask *task = [session dataTaskWithURL:requestURL completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error || !data) {
            completion(NO, nil);
            return;
        }
        
        NSError *jsonError;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonError];
        
        if (jsonError) {
            completion(NO, nil);
            return;
        }
        
        completion(YES, json);
    }];
    
    [task resume];
}

+ (UICKeyChainStore *)getSecureKeychain {
    UICKeyChainStore *store = [UICKeyChainStore keyChainStoreWithService:kServiceName];
    store.accessibility = UICKeyChainStoreAccessibilityWhenUnlockedThisDeviceOnly;
    store.synchronizable = NO; // Disable iCloud sync
    return store;
}

+ (void)secureDeleteStoredKey {
    UICKeyChainStore *store = [self getSecureKeychain];
    
    // Get the data first to overwrite memory
    NSString *userKey = [store stringForKey:@"userKey"];
    NSString *endTime = [store stringForKey:@"keyEndTime"];
    
    // Remove from keychain
    [store removeItemForKey:@"userKey"];
    [store removeItemForKey:@"keyEndTime"];
    
    // Secure memory overwrite (basic implementation)
    if (userKey) {
        char *keyData = (char *)[userKey UTF8String];
        if (keyData) {
            memset(keyData, 0, strlen(keyData));
        }
    }
    
    if (endTime) {
        char *timeData = (char *)[endTime UTF8String];
        if (timeData) {
            memset(timeData, 0, strlen(timeData));
        }
    }
}

+ (BOOL)isRuntimeHooked {
    // Basic check for common hooking frameworks
    void *substrate = dlopen("MobileSubstrate", RTLD_LAZY);
    if (substrate) {
        dlclose(substrate);
        return YES;
    }
    
    void *cycript = dlopen("libcycript", RTLD_LAZY);
    if (cycript) {
        dlclose(cycript);
        return YES;
    }
    
    return NO;
}

+ (BOOL)isBinaryModified {
    // Simple check using dyld information
    const struct mach_header *header = _dyld_get_image_header(0);
    if (!header) {
        return YES;
    }
    
    // Check if PIE is enabled
    if (!(header->flags & MH_PIE)) {
        return YES;
    }
    
    return NO;
}

+ (void)performIntegrityCheck {
    // Enable anti-debugging
    [self enableAntiDebugging];
    
    // Check device security
    if ([self isDeviceCompromised]) {
        exit(0);
    }
    
    // Check for runtime hooks
    if ([self isRuntimeHooked]) {
        exit(0);
    }
    
    // Verify application integrity
    if (![self verifyApplicationIntegrity]) {
        exit(0);
    }
}

@end