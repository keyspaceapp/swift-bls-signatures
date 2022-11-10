#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface G1Element: NSObject

+ (size_t)SIZE;

+ (G1Element *)from_bytes:(NSData *)b;

- (uint32_t)get_fingerprint;

- (NSData *)get_bytes;

- (BOOL)isEqual:(nullable id)object;

- (G1Element *)add:(NSData *)element;

@end

@interface G2Element: NSObject

+ (size_t)SIZE;

- (G2Element *)init;

+ (G2Element *)from_bytes:(NSData *)b;

- (NSData *)get_bytes;

@end

@interface PrivateKey: NSObject

- (instancetype)initWithBytes:(NSData *)b;

- (NSData *)get_bytes;
- (G1Element *)get_g1;

@end

@interface AugSchemeMPL: NSObject

+ (PrivateKey *)key_gen:(NSData *)b;
+ (PrivateKey *)derive_child_sk:(PrivateKey *)sk index:(uint32_t)index;
+ (PrivateKey *)derive_child_sk_unhardened:(PrivateKey *)sk index:(uint32_t)index;

+ (G2Element *)aggregate:(NSArray<G2Element *> *)signatures;
+ (G2Element *)sign:(PrivateKey *)pk msg:(NSData *)msg;

+ (BOOL)verify:(G1Element *)pk msg:(NSData *)msg sig:(G2Element *)sig;
+ (BOOL)aggregate_verify:(NSArray<G1Element *> *)pks msgs:(NSArray<NSData *> *)msgs sig:(G2Element *)sig;

@end

NS_ASSUME_NONNULL_END

