#import "ObjCBLS.h"

#include "bls.hpp"
#include "elements.hpp"
#include "hdkeys.hpp"
#include "privatekey.hpp"
#include "schemes.hpp"

@implementation PrivateKey {
#warning hacky and potentially unsafe
    NSData *_bytes; // having trouble storing bls::PrivateKey, so using raw bytes instead...
}

- (instancetype)initWithBytes:(NSData *)b
{
    self = [super init];
    
    if (b.length != bls::PrivateKey::PRIVATE_KEY_SIZE) {
        throw std::invalid_argument(
            "Length of bytes object not equal to PrivateKey::SIZE");
    }
    
    _bytes = b;
    return self;

}

- (G1Element *)get_g1
{
    // PythonGIL release_lock;
    bls::PrivateKey pk = bls::PrivateKey::FromBytes(bls::Bytes((uint8_t *)_bytes.bytes, bls::PrivateKey::PRIVATE_KEY_SIZE));
    bls::G1Element g1 = pk.GetG1Element();
    
#warning hacky conversion, diferent than python
    vector<uint8_t> g1_bytes = g1.Serialize();
    NSData *g1_data = [NSData dataWithBytes:g1_bytes.data() length:g1_bytes.size()];
    return [G1Element from_bytes:g1_data];
}

- (NSData *)get_bytes
{
    return _bytes;
}

@end

@implementation G1Element {
#warning hacky and potentially unsafe
    NSData *_bytes; // having trouble storing bls::G1Element, so using raw bytes instead...
}

- (instancetype)init
{
    bls::G1Element element = bls::G1Element();
    vector<uint8_t> element_bytes = element.Serialize();
    NSData *element_data = [NSData dataWithBytes:element_bytes.data() length:element_bytes.size()];
    self = [[G1Element alloc] initWithBytes:element_data];
    return self;
}

+ (instancetype)new
{
    bls::G1Element element = bls::G1Element();
    vector<uint8_t> element_bytes = element.Serialize();
    NSData *element_data = [NSData dataWithBytes:element_bytes.data() length:element_bytes.size()];
    return [[G1Element alloc] initWithBytes:element_data];
}

+ (size_t)SIZE
{
    return bls::G1Element::SIZE;
}

+ (G1Element *)from_bytes:(NSData *)b
{
    return [[G1Element alloc] initWithBytes:b];
}

- (instancetype)initWithBytes:(NSData *)b
{
    self = [super init];
    
    if (b.length != bls::G1Element::SIZE) {
        throw std::invalid_argument(
            "Length of bytes object not equal to G1Element::SIZE");
    }
    
    _bytes = b;
    return self;

}

- (uint32_t)get_fingerprint
{
    const bls::Bytes bytes = bls::Bytes((uint8_t *)_bytes.bytes, bls::G1Element::SIZE);
    bls::G1Element element = bls::G1Element().FromBytes(bytes);
    return element.GetFingerprint();
}

- (NSData *)get_bytes
{
    return _bytes;
}

- (BOOL)isEqual:(nullable id)object
{
    if (object == nil) {
        return NO;
    }

    if (self == object) {
        return YES;
    }

    if (![object isKindOfClass:[G1Element class]]) {
        return NO;
    }

    return [[self get_bytes] isEqualToData:[(G1Element *)object get_bytes]];
}

- (G1Element *)add:(NSData *)element
{
    const bls::Bytes self_bytes = bls::Bytes((uint8_t *)_bytes.bytes, bls::G1Element::SIZE);
    const bls::Bytes element_bytes = bls::Bytes((uint8_t *)element.bytes, bls::G1Element::SIZE);
    bls::G1Element combined =  bls::G1Element().FromBytes(self_bytes) + bls::G1Element().FromBytes(element_bytes);
    vector<uint8_t> combined_bytes = combined.Serialize();
    NSData *combined_data = [NSData dataWithBytes:combined_bytes.data() length:combined_bytes.size()];
    return [[G1Element alloc] initWithBytes:combined_data];
    
}

@end

@implementation G2Element {
    #warning hacky and potentially unsafe
    NSData *_bytes; // having trouble storing bls::G1Element, so using raw bytes instead...
}

- (instancetype)init
{
    self = [super init];
    
    bls::G2Element element = bls::G2Element();
    vector<uint8_t> element_bytes = element.Serialize();
    NSData *element_data = [NSData dataWithBytes:element_bytes.data() length:element_bytes.size()];
    self = [[G2Element alloc] initWithBytes:element_data];
    
    return self;
}

- (instancetype)initWithBytes:(NSData *)b
{
    self = [super init];
    
    if (b.length != bls::G2Element::SIZE) {
        throw std::invalid_argument(
            "Length of bytes object not equal to G1Element::SIZE");
    }
    
    _bytes = b;
    return self;

}

+ (size_t)SIZE
{
    return bls::G2Element::SIZE;
}

+ (G2Element *)from_bytes:(NSData *)b
{
    return [[G2Element alloc] initWithBytes:b];
}

- (NSData *)get_bytes
{
    return _bytes;
}

@end

@implementation AugSchemeMPL

+ (PrivateKey *)key_gen:(NSData *)b
{
    const uint8_t *input = (const uint8_t *)b.bytes;
    const vector<uint8_t> inputVec(input, input + b.length);
    bls::PrivateKey pk = bls::AugSchemeMPL().KeyGen(inputVec);
    vector<uint8_t> pk_bytes = pk.Serialize();
    NSData *pkData = [NSData dataWithBytes:pk_bytes.data() length:pk_bytes.size()];
    return [[PrivateKey alloc] initWithBytes:pkData];
}

+ (BOOL)verify:(G1Element *)pk msg:(NSData *)msg sig:(G2Element *)sig;
{
    NSData *pk_data = pk.get_bytes;
    const uint8_t *pk_bytes = (const uint8_t *)pk_data.bytes;
    const bls::Bytes pkBytes =  bls::Bytes(pk_bytes, pk_data.length);
    const bls::G1Element pk2 = bls::G1Element::FromBytes(pkBytes);
    
    NSData *sig_data = sig.get_bytes;
    const uint8_t *sig_bytes = (const uint8_t *)sig_data.bytes;
    const bls::Bytes sigBytes = bls::Bytes(sig_bytes, sig_data.length);
    const bls::G2Element sig2 = bls::G2Element::FromBytes(sigBytes);
    
//    std::string s((char *)msg.bytes);
//    // PythonGIL release_lock;
//    vector<uint8_t> v(s.begin(), s.end());
    
    // python uses string but couldn't get that working here
    const uint8_t *msg_bytes = (const uint8_t *)msg.bytes;
    const vector<uint8_t> v(msg_bytes, msg_bytes + msg.length);
    
    return bls::AugSchemeMPL().Verify(pk2, v, sig2);
}

+ (BOOL)aggregate_verify:(NSArray<G1Element *> *)pks msgs:(NSArray<NSData *> *)msgs sig:(G2Element *)sig
{
    vector<bls::G1Element> pks_vec(msgs.count);
    for (int i = 0; i < (int)pks.count; ++i) {
        G1Element *pk = pks[i];
        const bls::Bytes pkBytes = bls::Bytes((uint8_t *)pk.get_bytes.bytes, bls::G1Element::SIZE);
        bls::G1Element bls_pk = bls::G1Element::FromBytes(pkBytes);
        pks_vec[i] = bls_pk;
    }

    vector<vector<uint8_t>> msgs_vec(msgs.count);
    for (int i = 0; i < (int)msgs.count; ++i) {
        const uint8_t *msg_bytes = (const uint8_t *)msgs[i].bytes;
        const vector<uint8_t> v(msg_bytes, msg_bytes + msgs[i].length);
        msgs_vec[i] = vector<uint8_t>(msg_bytes, msg_bytes + msgs[i].length);
    }


    const bls::Bytes sigBytes = bls::Bytes((uint8_t *)[sig get_bytes].bytes, [sig get_bytes].length);
    const bls::G2Element bls_sig = bls::G2Element::FromBytes(sigBytes);

    // PythonGIL release_lock;
    return bls::AugSchemeMPL().AggregateVerify(pks_vec, msgs_vec, bls_sig);
}

+ (PrivateKey *)derive_child_sk:(PrivateKey *)sk index:(uint32_t)index
{
    const bls::Bytes skBytes = bls::Bytes((uint8_t *)sk.get_bytes.bytes, bls::PrivateKey::PRIVATE_KEY_SIZE);
    bls::PrivateKey bls_key = bls::PrivateKey::FromBytes(skBytes);
    bls::PrivateKey child_key = bls::AugSchemeMPL().DeriveChildSk(bls_key, index);
    vector<uint8_t> child_key_bytes = child_key.Serialize();
    NSData *child_key_data = [NSData dataWithBytes:child_key_bytes.data() length:child_key_bytes.size()];
    return [[PrivateKey alloc] initWithBytes:child_key_data];
}

+ (PrivateKey *)derive_child_sk_unhardened:(PrivateKey *)sk index:(uint32_t)index
{
    const bls::Bytes skBytes = bls::Bytes((uint8_t *)sk.get_bytes.bytes, bls::PrivateKey::PRIVATE_KEY_SIZE);
    bls::PrivateKey bls_key = bls::PrivateKey::FromBytes(skBytes);
    bls::PrivateKey child_key = bls::AugSchemeMPL().DeriveChildSkUnhardened(bls_key, index);
    vector<uint8_t> child_key_bytes = child_key.Serialize();
    NSData *child_key_data = [NSData dataWithBytes:child_key_bytes.data() length:child_key_bytes.size()];
    return [[PrivateKey alloc] initWithBytes:child_key_data];
}

+ (G2Element *)aggregate:(NSArray<G2Element *> *)signatures
{
    __block vector<bls::G2Element> signatures_vector;
    signatures_vector.reserve([signatures count]);
    for(G2Element *signature in signatures) {
        const bls::Bytes sigBytes = bls::Bytes((uint8_t *)[signature get_bytes].bytes, [signature get_bytes].length);
        const bls::G2Element sig2 = bls::G2Element::FromBytes(sigBytes);
        signatures_vector.push_back(sig2);
    }
    
    bls::G2Element aggregated = bls::AugSchemeMPL().Aggregate(signatures_vector);
    
    vector<uint8_t> aggregated_bytes = aggregated.Serialize();
    NSData *aggregated_data = [NSData dataWithBytes:aggregated_bytes.data() length:aggregated_bytes.size()];
    return [[G2Element alloc] initWithBytes:aggregated_data];
}

+ (G2Element *)sign:(PrivateKey *)pk msg:(NSData *)msg
{
    const bls::Bytes pkBytes = bls::Bytes((uint8_t *)pk.get_bytes.bytes, bls::PrivateKey::PRIVATE_KEY_SIZE);
    bls::PrivateKey bls_key = bls::PrivateKey::FromBytes(pkBytes);
    
    const uint8_t *msg_bytes = (const uint8_t *)msg.bytes;
    const vector<uint8_t> v(msg_bytes, msg_bytes + msg.length);
    bls::G2Element signature = bls::AugSchemeMPL().Sign(bls_key, v);
    
    vector<uint8_t> signature_bytes = signature.Serialize();
    NSData *signature_data = [NSData dataWithBytes:signature_bytes.data() length:signature_bytes.size()];
    return [[G2Element alloc] initWithBytes:signature_data];
}

@end
