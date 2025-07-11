// xztime.h

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

extern NSString * const __kHashDefaultValue;
extern NSString * const __Input;
extern NSString * const __kBaseURL;



@interface xztime : NSObject

+ (void)paid:(void (^)(void))execute;

// Security Enhancement Methods
+ (BOOL)isDeviceCompromised;
+ (BOOL)verifyApplicationIntegrity;
+ (void)enableAntiDebugging;
+ (void)setupSSLPinning:(NSURLSessionConfiguration *)config;
+ (NSString *)createRequestSignature:(NSDictionary *)params;
+ (void)makeSecureRequest:(NSString *)url params:(NSDictionary *)params completion:(void(^)(BOOL success, NSDictionary *response))completion;
+ (UICKeyChainStore *)getSecureKeychain;
+ (void)secureDeleteStoredKey;
+ (BOOL)isRuntimeHooked;
+ (BOOL)isBinaryModified;
+ (void)performIntegrityCheck;

@end