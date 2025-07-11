// xztime.h

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>

extern NSString * const __kHashDefaultValue;
extern NSString * const __Input;
extern NSString * const __kBaseURL;



@interface xztime : NSObject

+ (void)paid:(void (^)(void))execute;

@end