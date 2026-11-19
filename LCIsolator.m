// LCIsolator v6 - tanpa Dobby/JIT (pakai fishhook), dengan log ke file.
// Log: <container>/Documents/lcisolator.log
//
// Perubahan v6 (perbaikan logout GoPay, hasil bedah IPA GoPay 2.23.3):
//  1. Fake keychain sekarang MEMBEDAKAN kSecAttrAccessGroup & kSecAttrSynchronizable.
//     GoPay memakai 3 access group (gojekSharedKeychain, gojekSharedKeychainBiometric,
//     gotoSharedKeychain) dan GotoLoginSSO punya delete(accessGroup:)/deleteAll(accessGroup:).
//     Dulu group diabaikan -> hapus satu group = hapus token di SEMUA group,
//     dan item dengan service/account sama di group beda dianggap duplikat.
//  2. IDFV dibuat sekali (thread-safe, dispatch_once) lalu disimpan ke FILE, bukan
//     NSUserDefaults. login_sdk memakai IDFV sebagai clientDeviceId yang ikut disimpan
//     bersama token; kalau IDFV berubah antar launch/thread, token dianggap tidak valid.
//  3. Container ID dikunci ke file (Library/lc_container_id) supaya nama file keychain,
//     IDFV, dan WebView store tidak berubah antar launch. File keychain versi lama
//     (lc_fake_keychain_*.plist) dimigrasikan otomatis.
//  4. Log Delete sekarang mencatat group/service/account, supaya kelihatan siapa
//     yang menghapus sesi.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#import <signal.h>
#import <execinfo.h>
#import <fcntl.h>
#import <unistd.h>
#import "fishhook.h"

// Saklar untuk bisecting kalau masih crash: matikan satu per satu.
#define LC_ENABLE_SWIZZLE   1
#define LC_ENABLE_KEYCHAIN  1
#define LC_BLOCK_PASTEBOARD 1   // 0 kalau paste di app jadi tidak bisa
#define LC_CRASH_LOG        1

// Access group default = group PERTAMA di entitlement GoPay (tanpa prefix Team ID).
#define LC_DEFAULT_KC_GROUP @"gojekSharedKeychain"

#pragma mark - Logging (ke file, supaya kelihatan tanpa Console)

static int gLogFD = -1;

static void LCLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void LCLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[LCIsolator] %@", msg);
    if (gLogFD >= 0) {
        NSString *line = [NSString stringWithFormat:@"%@ %@\n", [NSDate date], msg];
        const char *c = line.UTF8String;
        if (c) write(gLogFD, c, strlen(c));
    }
}

static void openLogFile(void) {
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    [[NSFileManager defaultManager] createDirectoryAtPath:docs
                              withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *p = [docs stringByAppendingPathComponent:@"lcisolator.log"];
    gLogFD = open(p.fileSystemRepresentation, O_WRONLY | O_CREAT | O_APPEND, 0644);
}

#if LC_CRASH_LOG
static void crashSignal(int sig) {
    if (gLogFD >= 0) {
        const char *m = "!!! CRASH signal, backtrace:\n";
        write(gLogFD, m, strlen(m));
        void *bt[48]; int n = backtrace(bt, 48);
        backtrace_symbols_fd(bt, n, gLogFD);
    }
    signal(sig, SIG_DFL);
    raise(sig);
}
static void crashException(NSException *e) {
    LCLog(@"!!! UNCAUGHT EXCEPTION %@: %@\n%@", e.name, e.reason, e.callStackSymbols);
}
#endif

#pragma mark - Container helpers

static NSString *libPath(NSString *name) {
    NSString *lib = [NSHomeDirectory() stringByAppendingPathComponent:@"Library"];
    [[NSFileManager defaultManager] createDirectoryAtPath:lib
                              withIntermediateDirectories:YES attributes:nil error:nil];
    return name.length ? [lib stringByAppendingPathComponent:name] : lib;
}

static NSString *readTrimmed(NSString *path) {
    NSString *s = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    return [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

// Container ID dikunci ke file pada launch pertama, jadi tidak bisa "bergeser"
// antar launch (itu penyebab keychain/IDFV tiba-tiba kosong -> logout).
static NSString *getContainerID(void) {
    static NSString *cid; static dispatch_once_t t;
    dispatch_once(&t, ^{
        NSString *idFile = libPath(@"lc_container_id");
        NSString *saved = readTrimmed(idFile);
        if (saved.length) { cid = saved; return; }

        id v = [NSBundle mainBundle].infoDictionary[@"LCDataUUID"];
        if (![v isKindOfClass:[NSString class]] || ![v length])
            v = [[NSUserDefaults standardUserDefaults] stringForKey:@"LC_ActiveContainerName"];
        if (![v isKindOfClass:[NSString class]] || ![v length])
            v = NSHomeDirectory().lastPathComponent;   // folder data container unik per container
        cid = [v length] ? v : @"DefaultContainer";
        [cid writeToFile:idFile atomically:YES encoding:NSUTF8StringEncoding error:nil];
    });
    return cid;
}

// UUID deterministik dari string (stabil antar launch)
static NSUUID *uuidFromString(NSString *s) {
    NSUUID *u = [[NSUUID alloc] initWithUUIDString:s];
    if (u) return u;
    const char *c = s.UTF8String;
    unsigned char h[CC_MD5_DIGEST_LENGTH];
    CC_MD5(c, (CC_LONG)strlen(c), h);
    h[6] = (h[6] & 0x0F) | 0x30;
    h[8] = (h[8] & 0x3F) | 0x80;
    return [[NSUUID alloc] initWithUUIDBytes:h];
}

// IDFV palsu: dibuat SEKALI, thread-safe, disimpan di file (atomic).
// Migrasi: pakai nilai lama dari NSUserDefaults (v5 ke bawah) kalau ada,
// supaya deviceId yang sudah terlanjur tersimpan bersama token tetap cocok.
static NSUUID *fakeIDFV(void) {
    static NSUUID *u; static dispatch_once_t t;
    dispatch_once(&t, ^{
        NSString *file = libPath(@"lc_idfv.txt");
        NSString *v = readTrimmed(file);
        if (!v.length) {
            NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
            v = [d stringForKey:[NSString stringWithFormat:@"LC_FakeIDFV_%@", getContainerID()]];
            if (!v.length) {
                for (NSString *k in [d dictionaryRepresentation]) {
                    if ([k hasPrefix:@"LC_FakeIDFV_"]) {
                        NSString *cand = [d stringForKey:k];
                        if (cand.length) { v = cand; break; }
                    }
                }
            }
        }
        if (v.length && ![[NSUUID alloc] initWithUUIDString:v]) v = nil;
        if (!v.length) v = [[NSUUID UUID] UUIDString];
        [v writeToFile:file atomically:YES encoding:NSUTF8StringEncoding error:nil];
        u = [[NSUUID alloc] initWithUUIDString:v];
        LCLog(@"IDFV = %@", v);
    });
    return u;
}

static NSString *fakeKeychainPath(void) {
    static NSString *p; static dispatch_once_t t;
    dispatch_once(&t, ^{
        NSString *lib = libPath(@"");
        p = [lib stringByAppendingPathComponent:
             [NSString stringWithFormat:@"lc_fake_keychain_%@.plist", getContainerID()]];
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:p]) {
            // Migrasi dari file keychain versi lama yang namanya beda (ID bergeser).
            NSString *best = nil; NSDate *bestDate = nil;
            for (NSString *f in [fm contentsOfDirectoryAtPath:lib error:nil]) {
                if (![f hasPrefix:@"lc_fake_keychain_"] || ![f hasSuffix:@".plist"]) continue;
                NSString *full = [lib stringByAppendingPathComponent:f];
                NSDate *m = [fm attributesOfItemAtPath:full error:nil][NSFileModificationDate];
                if (!m) m = [NSDate distantPast];
                if (!bestDate || [m compare:bestDate] == NSOrderedDescending) { best = full; bestDate = m; }
            }
            if (best) {
                [fm copyItemAtPath:best toPath:p error:nil];
                LCLog(@"keychain dimigrasi dari %@", best.lastPathComponent);
            }
        }
    });
    return p;
}

static void swizzleMethod(Class cls, SEL origSel, SEL newSel) {
    Method o = class_getInstanceMethod(cls, origSel);
    Method n = class_getInstanceMethod(cls, newSel);
    if (!o || !n) {
        LCLog(@"swizzle SKIP %@ <-> %@ (method tidak ketemu)",
              NSStringFromSelector(origSel), NSStringFromSelector(newSel));
        return;
    }
    if (class_addMethod(cls, origSel, method_getImplementation(n), method_getTypeEncoding(n))) {
        class_replaceMethod(cls, newSel, method_getImplementation(o), method_getTypeEncoding(o));
    } else {
        method_exchangeImplementations(o, n);
    }
    LCLog(@"swizzle OK %@", NSStringFromSelector(origSel));
}

static void swizzleClassMethod(Class cls, SEL o, SEL n) {
    swizzleMethod(object_getClass(cls), o, n);
}

#pragma mark - ObjC categories

@implementation UIDevice (LCIsolation)
- (NSUUID *)lc_identifierForVendor {
    return fakeIDFV();
}
@end

#if LC_BLOCK_PASTEBOARD
@implementation UIPasteboard (LCIsolation)
- (NSString *)lc_string { return @""; }
- (BOOL)lc_hasStrings { return NO; }
@end
#endif

// Data store WebView per container (butuh iOS 17+). Yang diganti adalah
// +[WKWebsiteDataStore defaultDataStore], jadi WebView DAN cookie manager
// (httpCookieStore) sama-sama memakai store milik container ini.
// Mode incognito (nonPersistentDataStore) sengaja tidak disentuh.
static WKWebsiteDataStore *isolatedStore(void) {
    static WKWebsiteDataStore *s; static dispatch_once_t t;
    void (^make)(void) = ^{
        dispatch_once(&t, ^{
            if (@available(iOS 17.0, *)) {
                s = [WKWebsiteDataStore dataStoreForIdentifier:uuidFromString(getContainerID())];
            }
            LCLog(@"WebView data store: %@", s ? @"ISOLATED" : @"TIDAK terisolasi (butuh iOS 17+)");
        });
    };
    if ([NSThread isMainThread]) make(); else dispatch_sync(dispatch_get_main_queue(), make);
    return s;
}

@implementation WKWebsiteDataStore (LCIsolation)
+ (WKWebsiteDataStore *)lc_defaultDataStore {
    WKWebsiteDataStore *iso = isolatedStore();
    return iso ?: [self lc_defaultDataStore];   // setelah swizzle: memanggil yang asli
}
@end

// App group (group.com.go-jek.gopay.files) diarahkan ke folder
// milik container ini sendiri, supaya tidak ada folder yang dipakai bersama.
@implementation NSFileManager (LCIsolation)
- (NSURL *)lc_containerURLForSecurityApplicationGroupIdentifier:(NSString *)gid {
    if (!gid.length) return [self lc_containerURLForSecurityApplicationGroupIdentifier:gid];
    NSString *base = [[NSHomeDirectory() stringByAppendingPathComponent:@"Library/LCAppGroups"]
                      stringByAppendingPathComponent:gid];
    [self createDirectoryAtPath:base withIntermediateDirectories:YES attributes:nil error:nil];
    return [NSURL fileURLWithPath:base isDirectory:YES];
}
@end

// NOTE: swizzle NSUserDefaults initWithSuiteName: sengaja DIHAPUS.
// Container LiveContainer sudah punya sandbox sendiri, dan scoping suite name
// sering merusak SDK yang memakai app group.

#pragma mark - Fake Keychain (hanya generic & internet password)

static NSObject *gLock;
static NSMutableDictionary *gKC;

static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef);
static SecKeyRef (*orig_SecKeyCreateRandomKey)(CFDictionaryRef, CFErrorRef *);

// ---- Isolasi kunci kriptografi (kSecClassKey / Secure Enclave) ----
// Kunci permanen disimpan di keychain ASLI yang dipakai bersama semua container.
// Supaya tidak bentrok, kSecAttrApplicationTag diberi awalan container.
static NSData *tagPrefixData(void) {
    return [[NSString stringWithFormat:@"lc.%@.", getContainerID()] dataUsingEncoding:NSUTF8StringEncoding];
}
static NSData *scopedTag(id tag) {
    NSMutableData *m = [tagPrefixData() mutableCopy];
    if ([tag isKindOfClass:[NSData class]]) [m appendData:tag];
    else if ([tag isKindOfClass:[NSString class]]) [m appendData:[tag dataUsingEncoding:NSUTF8StringEncoding]];
    return m;
}
static NSData *unscopedTag(NSData *t) {
    NSData *p = tagPrefixData();
    if (t.length >= p.length && [[t subdataWithRange:NSMakeRange(0, p.length)] isEqualToData:p])
        return [t subdataWithRange:NSMakeRange(p.length, t.length - p.length)];
    return t;
}
static BOOL isKeyClass(NSDictionary *d) {
    return [d[(__bridge id)kSecClass] isEqual:(__bridge id)kSecClassKey];
}
static NSDictionary *scopeKeyDict(NSDictionary *d) {
    id tag = d[(__bridge id)kSecAttrApplicationTag];
    if (!tag) return d;
    NSMutableDictionary *m = [d mutableCopy];
    m[(__bridge id)kSecAttrApplicationTag] = scopedTag(tag);
    return m;
}
static NSDictionary *scopeKeyParams(NSDictionary *p) {
    NSMutableDictionary *m = [scopeKeyDict(p) mutableCopy];
    for (id sub in @[(__bridge id)kSecPrivateKeyAttrs, (__bridge id)kSecPublicKeyAttrs]) {
        NSDictionary *sd = m[sub];
        if ([sd isKindOfClass:[NSDictionary class]]) m[sub] = scopeKeyDict(sd);
    }
    return m;
}
static id unscopeObj(id o) {
    if ([o isKindOfClass:[NSDictionary class]]) {
        NSData *t = o[(__bridge id)kSecAttrApplicationTag];
        if ([t isKindOfClass:[NSData class]]) {
            NSData *u = unscopedTag(t);
            if (u != t) {
                NSMutableDictionary *m = [o mutableCopy];
                m[(__bridge id)kSecAttrApplicationTag] = u;
                return m;
            }
        }
        return o;
    }
    if ([o isKindOfClass:[NSArray class]]) {
        NSMutableArray *a = [NSMutableArray array]; BOOL changed = NO;
        for (id e in o) { id n = unscopeObj(e); if (n != e) changed = YES; [a addObject:n]; }
        return changed ? a : o;
    }
    return o;
}
static void unscopeResult(CFTypeRef *result) {
    if (!result || !*result) return;
    CFTypeID t = CFGetTypeID(*result);
    if (t != CFDictionaryGetTypeID() && t != CFArrayGetTypeID()) return;
    id o = (__bridge id)*result;
    id n = unscopeObj(o);
    if (n == o) return;
    CFTypeRef old = *result;
    *result = CFRetain((__bridge CFTypeRef)n);
    CFRelease(old);
}

static BOOL isPasswordClass(NSDictionary *d) {
    id c = d[(__bridge id)kSecClass];
    return [c isEqual:(__bridge id)kSecClassGenericPassword] ||
           [c isEqual:(__bridge id)kSecClassInternetPassword];
}

// ---- Access group & synchronizable (inti perbaikan v6) ----
// Team ID di-buang (GF3689X945.gojekSharedKeychain -> gojekSharedKeychain) karena
// prefix itu berubah setelah di-resign. Tanpa group = group default (entitlement pertama).
static NSString *normGroup(id g) {
    if (![g isKindOfClass:[NSString class]] || ![g length]) return LC_DEFAULT_KC_GROUP;
    NSString *s = g;
    NSRange r = [s rangeOfString:@"."];
    if (r.location == 10) return [s substringFromIndex:11];   // Team ID = 10 karakter
    return s;
}
static BOOL itemSync(NSDictionary *d) {
    id s = d[(__bridge id)kSecAttrSynchronizable];
    return [s isKindOfClass:[NSNumber class]] ? [s boolValue] : NO;
}

static NSString *kcKey(NSDictionary *a) {
    NSArray *ks = @[(__bridge id)kSecClass, (__bridge id)kSecAttrService,
                    (__bridge id)kSecAttrAccount, (__bridge id)kSecAttrServer,
                    (__bridge id)kSecAttrProtocol, (__bridge id)kSecAttrPort,
                    (__bridge id)kSecAttrPath];
    NSMutableArray *parts = [NSMutableArray array];
    for (id k in ks) [parts addObject:[NSString stringWithFormat:@"%@", a[k] ?: @""]];
    [parts addObject:normGroup(a[(__bridge id)kSecAttrAccessGroup])];
    [parts addObject:itemSync(a) ? @"sync" : @"local"];
    return [parts componentsJoinedByString:@"|"];
}

static NSMutableDictionary *kcStore(void) {   // panggil di dalam @synchronized
    if (!gKC) {
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:fakeKeychainPath()];
        gKC = [NSMutableDictionary dictionary];
        // Re-key: file lama memakai key tanpa group/sync.
        [d enumerateKeysAndObjectsUsingBlock:^(id k, id v, BOOL *stop) {
            if ([v isKindOfClass:[NSDictionary class]]) gKC[kcKey(v)] = v;
        }];
        LCLog(@"keychain loaded, %lu item", (unsigned long)gKC.count);
    }
    return gKC;
}

static void kcSave(void) {
    if (![gKC writeToFile:fakeKeychainPath() atomically:YES])
        LCLog(@"WARN gagal save keychain");
}

// Buang kunci query-only dan nilai yang bukan tipe plist (SecAccessControlRef, dll)
static NSMutableDictionary *sanitize(NSDictionary *src) {
    NSSet *drop = [NSSet setWithObjects:
        (__bridge id)kSecReturnData, (__bridge id)kSecReturnAttributes,
        (__bridge id)kSecReturnRef, (__bridge id)kSecReturnPersistentRef,
        (__bridge id)kSecMatchLimit, nil];
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    [src enumerateKeysAndObjectsUsingBlock:^(id k, id v, BOOL *stop) {
        if (![k isKindOfClass:[NSString class]] || [drop containsObject:k]) return;
        if ([v isKindOfClass:[NSString class]] || [v isKindOfClass:[NSData class]] ||
            [v isKindOfClass:[NSNumber class]] || [v isKindOfClass:[NSDate class]])
            out[k] = v;
    }];
    return out;
}

static BOOL kcMatches(NSDictionary *item, NSDictionary *q) {
    NSData *pref = q[(__bridge id)kSecValuePersistentRef];
    if (pref && ![pref isEqual:[kcKey(item) dataUsingEncoding:NSUTF8StringEncoding]]) return NO;

    // Access group: kalau query menyebut group, item harus di group yang sama.
    id qg = q[(__bridge id)kSecAttrAccessGroup];
    if ([qg isKindOfClass:[NSString class]] && [qg length]) {
        if (![normGroup(qg) isEqualToString:normGroup(item[(__bridge id)kSecAttrAccessGroup])]) return NO;
    }
    // Synchronizable: tanpa atribut ini, keychain asli hanya mengembalikan item non-sync.
    id qs = q[(__bridge id)kSecAttrSynchronizable];
    if (!qs) {
        if (itemSync(item)) return NO;
    } else if ([qs isKindOfClass:[NSNumber class]]) {
        if ([qs boolValue] != itemSync(item)) return NO;
    }   // selain itu (kSecAttrSynchronizableAny) = cocokkan semua

    NSArray *ks = @[(__bridge id)kSecClass, (__bridge id)kSecAttrService,
                    (__bridge id)kSecAttrAccount, (__bridge id)kSecAttrLabel,
                    (__bridge id)kSecAttrDescription, (__bridge id)kSecAttrComment,
                    (__bridge id)kSecAttrCreator, (__bridge id)kSecAttrType,
                    (__bridge id)kSecAttrApplicationLabel, (__bridge id)kSecAttrApplicationTag,
                    (__bridge id)kSecAttrGeneric, (__bridge id)kSecAttrServer,
                    (__bridge id)kSecAttrProtocol, (__bridge id)kSecAttrPort,
                    (__bridge id)kSecAttrPath];
    for (id k in ks) {
        id qv = q[k];
        if (!qv) continue;
        id iv = item[k];
        if (!iv || ![iv isEqual:qv]) return NO;
    }
    return YES;
}

static id kcFormat(NSDictionary *item, NSDictionary *q) {
    BOOL wData = [q[(__bridge id)kSecReturnData] boolValue];
    BOOL wAttr = [q[(__bridge id)kSecReturnAttributes] boolValue];
    BOOL wRef  = [q[(__bridge id)kSecReturnRef] boolValue];
    BOOL wPRef = [q[(__bridge id)kSecReturnPersistentRef] boolValue];
    if (!wData && !wAttr && !wRef && !wPRef) return nil;

    if (wData && !wAttr) return item[(__bridge id)kSecValueData];
    NSMutableDictionary *m = [item mutableCopy];
    if (wAttr) {
        if (!wData) [m removeObjectForKey:(__bridge id)kSecValueData];
        if (wPRef) m[(__bridge id)kSecValuePersistentRef] = [kcKey(item) dataUsingEncoding:NSUTF8StringEncoding];
        return m;
    }
    return [kcKey(item) dataUsingEncoding:NSUTF8StringEncoding];
}

static NSString *qdesc(NSDictionary *q) {
    return [NSString stringWithFormat:@"grp=%@ svc=%@ acc=%@",
            q[(__bridge id)kSecAttrAccessGroup] ?: @"-",
            q[(__bridge id)kSecAttrService] ?: @"-",
            q[(__bridge id)kSecAttrAccount] ?: @"-"];
}

static OSStatus my_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    NSDictionary *a = (__bridge NSDictionary *)attributes;
    if (a && isKeyClass(a)) {
        OSStatus st = orig_SecItemAdd((__bridge CFDictionaryRef)scopeKeyDict(a), result);
        if (st == errSecSuccess) unscopeResult(result);
        return st;
    }
    if (!a || !isPasswordClass(a)) return orig_SecItemAdd(attributes, result);
    @synchronized (gLock) {
        NSMutableDictionary *kc = kcStore();
        NSString *key = kcKey(a);
        if (kc[key]) { LCLog(@"Add DUPLICATE %@", key); return errSecDuplicateItem; }
        NSMutableDictionary *item = sanitize(a);
        item[(__bridge id)kSecAttrCreationDate] = [NSDate date];
        item[(__bridge id)kSecAttrModificationDate] = [NSDate date];
        kc[key] = item;
        kcSave();
        LCLog(@"Add OK %@", key);
        if (result) {
            id f = kcFormat(item, a);
            *result = f ? CFRetain((__bridge CFTypeRef)f) : NULL;
        }
    }
    return errSecSuccess;
}

static OSStatus my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    NSDictionary *q = (__bridge NSDictionary *)query;
    if (q && isKeyClass(q)) {
        OSStatus st = orig_SecItemCopyMatching((__bridge CFDictionaryRef)scopeKeyDict(q), result);
        if (st == errSecSuccess) unscopeResult(result);
        return st;
    }
    if (!q || !isPasswordClass(q)) return orig_SecItemCopyMatching(query, result);
    @synchronized (gLock) {
        NSMutableArray *hits = [NSMutableArray array];
        for (NSString *k in kcStore()) if (kcMatches(gKC[k], q)) [hits addObject:gKC[k]];
        if (!hits.count) {
            LCLog(@"Copy NOT FOUND %@", qdesc(q));
            return errSecItemNotFound;
        }
        BOOL all = [q[(__bridge id)kSecMatchLimit] isEqual:(__bridge id)kSecMatchLimitAll];
        if (all) {
            NSMutableArray *out = [NSMutableArray array];
            for (NSDictionary *it in hits) { id f = kcFormat(it, q); if (f) [out addObject:f]; }
            if (result) *result = CFRetain((__bridge CFTypeRef)out);
        } else {
            id f = kcFormat(hits[0], q);
            if (result) *result = f ? CFRetain((__bridge CFTypeRef)f) : NULL;
        }
        LCLog(@"Copy OK count=%lu %@", (unsigned long)hits.count, qdesc(q));
        return errSecSuccess;
    }
}

static OSStatus my_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attrsToUpdate) {
    NSDictionary *q = (__bridge NSDictionary *)query;
    NSDictionary *upd = (__bridge NSDictionary *)attrsToUpdate;
    if (q && isKeyClass(q))
        return orig_SecItemUpdate((__bridge CFDictionaryRef)scopeKeyDict(q),
                                  attrsToUpdate ? (__bridge CFDictionaryRef)scopeKeyDict(upd) : NULL);
    if (!q || !isPasswordClass(q)) return orig_SecItemUpdate(query, attrsToUpdate);
    if (!upd) return errSecParam;
    @synchronized (gLock) {
        NSMutableDictionary *kc = kcStore();
        NSMutableArray *keys = [NSMutableArray array];
        for (NSString *k in kc) if (kcMatches(kc[k], q)) [keys addObject:k];
        if (!keys.count) return errSecItemNotFound;
        for (NSString *oldK in keys) {
            NSMutableDictionary *item = [kc[oldK] mutableCopy];
            [item addEntriesFromDictionary:sanitize(upd)];
            item[(__bridge id)kSecAttrModificationDate] = [NSDate date];
            NSString *newK = kcKey(item);
            if (![oldK isEqualToString:newK]) [kc removeObjectForKey:oldK];
            kc[newK] = item;
        }
        kcSave();
        LCLog(@"Update OK count=%lu %@", (unsigned long)keys.count, qdesc(q));
    }
    return errSecSuccess;
}

static OSStatus my_SecItemDelete(CFDictionaryRef query) {
    NSDictionary *q = (__bridge NSDictionary *)query;
    if (q && isKeyClass(q)) return orig_SecItemDelete((__bridge CFDictionaryRef)scopeKeyDict(q));
    if (!q || !isPasswordClass(q)) return orig_SecItemDelete(query);
    @synchronized (gLock) {
        NSMutableDictionary *kc = kcStore();
        NSMutableArray *keys = [NSMutableArray array];
        for (NSString *k in kc) if (kcMatches(kc[k], q)) [keys addObject:k];
        if (!keys.count) {
            LCLog(@"Delete NOT FOUND %@", qdesc(q));
            return errSecItemNotFound;
        }
        [kc removeObjectsForKeys:keys];
        kcSave();
        LCLog(@"Delete OK count=%lu %@", (unsigned long)keys.count, qdesc(q));
    }
    return errSecSuccess;
}

static SecKeyRef my_SecKeyCreateRandomKey(CFDictionaryRef params, CFErrorRef *error) {
    NSDictionary *p = (__bridge NSDictionary *)params;
    if (!p) return orig_SecKeyCreateRandomKey(params, error);
    return orig_SecKeyCreateRandomKey((__bridge CFDictionaryRef)scopeKeyParams(p), error);
}

#pragma mark - Init

__attribute__((constructor))
static void lc_init(void) {
    gLock = [NSObject new];
    openLogFile();                       // paling awal: kalau file ini muncul, dylib ter-load
    LCLog(@"=== init v6 container=%@ home=%@", getContainerID(), NSHomeDirectory());

#if LC_CRASH_LOG
    NSSetUncaughtExceptionHandler(&crashException);
    int sigs[] = {SIGSEGV, SIGBUS, SIGABRT, SIGILL, SIGTRAP};
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) signal(sigs[i], crashSignal);
#endif

#if LC_ENABLE_SWIZZLE
    (void)fakeIDFV();                    // buat/baca IDFV sekarang, sebelum ada thread lain
    swizzleMethod([UIDevice class], @selector(identifierForVendor), @selector(lc_identifierForVendor));
#if LC_BLOCK_PASTEBOARD
    swizzleMethod([UIPasteboard class], @selector(string), @selector(lc_string));
    swizzleMethod([UIPasteboard class], @selector(hasStrings), @selector(lc_hasStrings));
#endif
    if ([NSThread isMainThread]) (void)isolatedStore();   // buat store sebelum swizzle
    swizzleClassMethod([WKWebsiteDataStore class], @selector(defaultDataStore), @selector(lc_defaultDataStore));
    swizzleMethod([NSFileManager class], @selector(containerURLForSecurityApplicationGroupIdentifier:),
                  @selector(lc_containerURLForSecurityApplicationGroupIdentifier:));
#endif

#if LC_ENABLE_KEYCHAIN
    struct rebinding r[] = {
        {"SecItemAdd",          (void *)my_SecItemAdd,          (void **)&orig_SecItemAdd},
        {"SecItemCopyMatching", (void *)my_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching},
        {"SecItemUpdate",       (void *)my_SecItemUpdate,       (void **)&orig_SecItemUpdate},
        {"SecItemDelete",       (void *)my_SecItemDelete,       (void **)&orig_SecItemDelete},
        {"SecKeyCreateRandomKey", (void *)my_SecKeyCreateRandomKey, (void **)&orig_SecKeyCreateRandomKey},
    };
    int rc = rebind_symbols(r, 5);
    LCLog(@"rebind_symbols rc=%d", rc);
#endif

    LCLog(@"=== init selesai");
}
