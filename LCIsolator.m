#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <Security/Security.h>
#import <CoreFoundation/CoreFoundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <signal.h>
#import <execinfo.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <errno.h>
#import <stdatomic.h>
#import "fishhook.h"

// ============================================================================
// LCIsolator v11 — Deep Container Isolation untuk GoPay v2.23.1 di LiveContainer
// Disusun dari audit REA + 99 biner Mach-O + Dart AOT + 8 JS bridge + runtime log.
// Saklar bisecting: bisa dioverride via -DLC_...=0/1/2/3 saat compile.
// ============================================================================
#ifndef LC_ENABLE_SWIZZLE
#define LC_ENABLE_SWIZZLE           1
#endif
#ifndef LC_ENABLE_KEYCHAIN
#define LC_ENABLE_KEYCHAIN          1   // Fake KC (UTF-8 canonical + migrasi v10) + 2-phase kSecClassKey + SecKeyGeneratePair
#endif
#ifndef LC_ISOLATE_PREFS
#define LC_ISOLATE_PREFS            1   // NSUserDefaults (6 domain methods + canary check) + CFPreferences* (termasuk kCFPreferencesCurrentApplication)
#endif
#ifndef LC_ISOLATE_WEB_NET
#define LC_ISOLATE_WEB_NET          1   // NSHTTPCookieStorage, NSURLCache, NSURLCredentialStorage, NSURLSession (shared/default/bg), WKWebsiteDataStore, WKWebViewConfiguration, WKContentRuleListStore
#endif
#ifndef LC_FORCE_WEBVIEW_STORE
#define LC_FORCE_WEBVIEW_STORE      1   // Paksa WKWebsiteDataStore container di WKWebViewConfiguration & WKWebView (aman untuk popup 3DS/_relatedWebView)
#endif
#ifndef LC_WEBVIEW_IOS16_ISOLATE
#define LC_WEBVIEW_IOS16_ISOLATE    1   // 1 = fallback nonPersistentDataStore + sync cookie ke isolatedCookieStorage di iOS 15-16 (otomatis tidak aktif di iOS 17+)
#endif
#ifndef LC_EPHEMERAL_WEBAUTH
#define LC_EPHEMERAL_WEBAUTH        1   // Paksa ASWebAuthenticationSession.prefersEphemeralWebBrowserSession = YES (tahan overwrite AppAuth/flutter_inappwebview)
#endif
#ifndef LC_PASTEBOARD_MODE
#define LC_PASTEBOARD_MODE          3   // 0=off, 1=full in-container sandbox, 2=blokir total, 3=Smart Payment (named+changeCount+background diisolasi, copy-paste VA/OTP aktif tetap jalan)
#endif
#ifndef LC_ISOLATE_NOTIFICATIONS
#define LC_ISOLATE_NOTIFICATIONS    1   // Isolasi UNUserNotificationCenter per container
#endif
#ifndef LC_ISOLATE_SYSTEM_UI
#define LC_ISOLATE_SYSTEM_UI        1   // Isolasi UIApplication.shortcutItems & badge count per container
#endif
#ifndef LC_ISOLATE_DEVICE_IDS
#define LC_ISOLATE_DEVICE_IDS       1   // IDFV, IDFA (zero UUID), UIDevice.name, NSProcessInfo.hostName, C gethostname()
#endif
#ifndef LC_CRASH_LOG
#define LC_CRASH_LOG                1   // Chained sigaction + uncaught exception logger (tidak menimpa Crashlytics/Flutter)
#endif
#ifndef LC_TRACE_WEB
#define LC_TRACE_WEB                1   // Log diagnostik WebView/browser/contentWorld/cookie-clear (tanpa nilai token/cookie)
#endif
#ifndef LC_TRACE_AUTH
#define LC_TRACE_AUTH               1   // Log diagnostik LAContext (dengan throttle/dedup anti-spam) & status izin
#endif

// Access group default = group PERTAMA di entitlement GoPay (tanpa prefix Team ID).
#ifndef LC_DEFAULT_KC_GROUP
#define LC_DEFAULT_KC_GROUP @"gojekSharedKeychain"
#endif

#pragma mark - Logging (cached FD, thread-safe, hemat I/O main thread)

static int gLogFD = -1;
static NSObject *gLogLock;
static NSString *gLogHomeSnapshot;
static BOOL gLogHomeFrozen = NO;

static void openOrRefreshLogFileLocked(BOOL forceCheck) {
    if (gLogFD >= 0 && gLogHomeFrozen && !forceCheck) return;
    NSString *home = NSHomeDirectory();
    if (!home.length) return;
    if (gLogFD >= 0 && [gLogHomeSnapshot isEqualToString:home]) return;
    if (gLogFD >= 0) { close(gLogFD); gLogFD = -1; }
    NSString *docs = [home stringByAppendingPathComponent:@"Documents"];
    [[NSFileManager defaultManager] createDirectoryAtPath:docs
                              withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *p = [docs stringByAppendingPathComponent:@"lcisolator.log"];
    gLogFD = open(p.fileSystemRepresentation, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (gLogFD >= 0) gLogHomeSnapshot = [home copy];
}

static void refreshLogFile(BOOL freezeAfter) {
    @synchronized (gLogLock) {
        openOrRefreshLogFileLocked(YES);
        if (freezeAfter && gLogFD >= 0) gLogHomeFrozen = YES;
    }
}

static void LCLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void LCLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[LCIsolator] %@", msg);
    @synchronized (gLogLock) {
        if (gLogFD < 0 || !gLogHomeFrozen) {
            openOrRefreshLogFileLocked(NO);
        }
        if (gLogFD >= 0) {
            NSString *line = [NSString stringWithFormat:@"%@ %@\n", [NSDate date], msg];
            const char *c = line.UTF8String;
            if (c) (void)write(gLogFD, c, strlen(c));
        }
    }
}

#if LC_CRASH_LOG
static const int gCrashSigs[] = { SIGSEGV, SIGBUS, SIGABRT, SIGILL };
static struct sigaction gPrevSigActions[4];
static NSUncaughtExceptionHandler *gPrevUncaughtHandler = NULL;

static void crashSignal(int sig, siginfo_t *info, void *uap) {
    (void)info; (void)uap;
    if (gLogFD >= 0) {
        const char *m = "!!! CRASH signal, backtrace:\n";
        (void)write(gLogFD, m, strlen(m));
        void *bt[48];
        int n = backtrace(bt, 48);
        backtrace_symbols_fd(bt, n, gLogFD);
    }
    // Restore previous handler (Crashlytics / Flutter / LiveContainer) lalu re-raise.
    for (size_t i = 0; i < sizeof(gCrashSigs) / sizeof(gCrashSigs[0]); i++) {
        if (gCrashSigs[i] == sig) {
            sigaction(sig, &gPrevSigActions[i], NULL);
            break;
        }
    }
    raise(sig);
}

static void crashException(NSException *e) {
    LCLog(@"!!! UNCAUGHT EXCEPTION %@: %@\n%@", e.name, e.reason, e.callStackSymbols);
    if (gPrevUncaughtHandler) gPrevUncaughtHandler(e);
}
#endif

#pragma mark - Hook Helpers (aman untuk class cluster & idempoten)

static BOOL hookInstanceMethod(Class cls, SEL sel, IMP newIMP, IMP *outOrig) {
    if (!cls || !sel || !newIMP || !outOrig) return NO;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) {
        LCLog(@"hook SKIP -[%@ %@]", NSStringFromClass(cls), NSStringFromSelector(sel));
        return NO;
    }
    IMP cur = method_getImplementation(m);
    if (cur == newIMP) return YES;
    *outOrig = cur;
    class_replaceMethod(cls, sel, newIMP, method_getTypeEncoding(m));
    LCLog(@"hook OK -[%@ %@]", NSStringFromClass(cls), NSStringFromSelector(sel));
    return YES;
}

static BOOL hookClassMethod(Class cls, SEL sel, IMP newIMP, IMP *outOrig) {
    return hookInstanceMethod(object_getClass(cls), sel, newIMP, outOrig);
}

#pragma mark - Container Identity & Helpers (anti-clone, anti-race, tanpa lintas-curi)

static __thread BOOL tInInternalIO = NO;

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

static NSString *sanitizeContainerToken(NSString *raw) {
    if (![raw isKindOfClass:[NSString class]] || !raw.length) return nil;
    NSCharacterSet *bad = [[NSCharacterSet characterSetWithCharactersInString:
                            @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"] invertedSet];
    NSString *clean = [[raw componentsSeparatedByCharactersInSet:bad] componentsJoinedByString:@"_"];
    return clean.length ? clean : nil;
}

// Container ID divalidasi terhadap NSHomeDirectory() aktual:
// - Stabil antar launch di container yang sama.
// - Jika container di-clone ke folder baru (homeAnchor berubah), otomatis memakai ID baru
//   supaya 2 container hasil clone TIDAK pernah berbagi WKWebsiteDataStore / kSecClassKey!
static NSObject *gCIDLock;
static NSString *gCachedCID;
static NSString *gCachedHome;

static NSString *getContainerID(void) {
    NSString *home = NSHomeDirectory() ?: @"";
    @synchronized (gCIDLock) {
        if (gCachedCID.length && [gCachedHome isEqualToString:home]) {
            return gCachedCID;
        }
        BOOL prevIO = tInInternalIO;
        tInInternalIO = YES;

        NSString *homeLeaf = sanitizeContainerToken(home.lastPathComponent);
        NSString *bundleUUID = sanitizeContainerToken([NSBundle mainBundle].infoDictionary[@"LCDataUUID"]);
        NSString *anchor = bundleUUID.length ? bundleUUID : homeLeaf;

        NSString *idFile = libPath(@"lc_container_id");
        NSString *anchorFile = libPath(@"lc_home_anchor");
        NSString *savedID = sanitizeContainerToken(readTrimmed(idFile));
        NSString *savedAnchor = sanitizeContainerToken(readTrimmed(anchorFile));

        NSString *cid = nil;
        if (savedID.length && (!savedAnchor.length || !anchor.length || [savedAnchor isEqualToString:anchor])) {
            // Container sama (atau migrasi bersih dari v9 yang belum punya lc_home_anchor).
            cid = savedID;
            if (anchor.length && ![savedAnchor isEqualToString:anchor]) {
                [anchor writeToFile:anchorFile atomically:YES encoding:NSUTF8StringEncoding error:nil];
            }
        } else {
            // Container baru ATAU hasil clone ke folder container berbeda -> buat ID unik baru!
            cid = anchor.length ? anchor : [[NSUUID UUID] UUIDString];
            [cid writeToFile:idFile atomically:YES encoding:NSUTF8StringEncoding error:nil];
            if (anchor.length) {
                [anchor writeToFile:anchorFile atomically:YES encoding:NSUTF8StringEncoding error:nil];
            }
            if (savedID.length && savedAnchor.length && anchor.length && ![savedAnchor isEqualToString:anchor]) {
                // Hapus file IDFV lama hasil clone supaya container clone mendapat identitas segar.
                [[NSFileManager defaultManager] removeItemAtPath:libPath(@"lc_idfv.txt") error:nil];
            }
        }

        gCachedCID = cid;
        gCachedHome = [home copy];
        tInInternalIO = prevIO;
        return gCachedCID;
    }
}

static NSString *containerPrefix(void) {
    return [NSString stringWithFormat:@"lc.%@.", getContainerID()];
}

#if LC_ISOLATE_WEB_NET
static NSUUID *uuidFromString(NSString *s) {
    NSUUID *u = [[NSUUID alloc] initWithUUIDString:s];
    if (u) return u;
    const char *c = s.UTF8String ?: "default";
    unsigned char h[CC_MD5_DIGEST_LENGTH];
    CC_MD5(c, (CC_LONG)strlen(c), h);
    h[6] = (h[6] & 0x0F) | 0x30;
    h[8] = (h[8] & 0x3F) | 0x80;
    return [[NSUUID alloc] initWithUUIDBytes:h];
}
#endif

#if LC_ISOLATE_DEVICE_IDS
// IDFV per container: TIDAK pernah memindai key LC_FakeIDFV_* milik container lain.
static NSObject *gIDFVLock;
static NSUUID *gCachedIDFV;
static NSString *gCachedIDFVContainer;

static NSUUID *fakeIDFV(void) {
    NSString *cid = getContainerID();
    @synchronized (gIDFVLock) {
        if (gCachedIDFV && [gCachedIDFVContainer isEqualToString:cid]) return gCachedIDFV;
        BOOL prevIO = tInInternalIO;
        tInInternalIO = YES;

        NSString *file = libPath(@"lc_idfv.txt");
        NSString *v = readTrimmed(file);
        if (!v.length) {
            // Migrasi hanya untuk key persis milik cid ini (tidak pernah curi key container lain).
            NSString *exactKey = [NSString stringWithFormat:@"LC_FakeIDFV_%@", cid];
            v = [[NSUserDefaults standardUserDefaults] stringForKey:exactKey];
        }
        if (v.length && ![[NSUUID alloc] initWithUUIDString:v]) v = nil;
        if (!v.length) v = [[NSUUID UUID] UUIDString];
        [v writeToFile:file atomically:YES encoding:NSUTF8StringEncoding error:nil];

        gCachedIDFV = [[NSUUID alloc] initWithUUIDString:v];
        gCachedIDFVContainer = [cid copy];
        tInInternalIO = prevIO;
        LCLog(@"IDFV = %@ (cid=%@)", v, cid);
        return gCachedIDFV;
    }
}

static NSString *containerHostName(void) {
    NSString *cid = getContainerID();
    NSString *shortID = cid.length > 8 ? [cid substringToIndex:8] : cid;
    return [NSString stringWithFormat:@"iPhone-%@.local", shortID];
}
#endif

#if LC_ENABLE_KEYCHAIN
// Path keychain khusus cid ini (TIDAK pernah auto-copy keychain file container lain).
static NSString *fakeKeychainPath(void) {
    return libPath([NSString stringWithFormat:@"lc_fake_keychain_%@.plist", getContainerID()]);
}
#endif

#pragma mark - 1. Device Identifiers (IDFV, IDFA, UIDevice.name, NSProcessInfo.hostName, gethostname)

#if LC_ISOLATE_DEVICE_IDS
static NSUUID *(*orig_identifierForVendor)(id, SEL);
static NSUUID *my_identifierForVendor(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    return fakeIDFV();
}

static NSString *(*orig_deviceName)(id, SEL);
static NSString *my_deviceName(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    return @"iPhone";
}

static NSString *(*orig_hostName)(id, SEL);
static NSString *my_hostName(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    return containerHostName();
}

// Rebind C-API gethostname() (diimpor oleh Flutter.framework & Ojo.framework) agar sinkron dengan NSProcessInfo.hostName.
static int (*orig_gethostname)(char *, size_t);
static int my_gethostname(char *name, size_t namelen) {
    if (!name || namelen == 0) {
        errno = EINVAL;
        return -1;
    }
    @autoreleasepool {
        NSString *h = containerHostName();
        const char *c = h.UTF8String;
        if (c) {
            size_t len = strlen(c);
            if (len >= namelen) {
                memcpy(name, c, namelen - 1);
                name[namelen - 1] = '\0';
                errno = ENAMETOOLONG;
                return -1;
            }
            memcpy(name, c, len + 1);
            return 0;
        }
    }
    return orig_gethostname ? orig_gethostname(name, namelen) : -1;
}

static NSUUID *(*orig_advertisingIdentifier)(id, SEL);
static NSUUID *my_advertisingIdentifier(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    static NSUUID *zeroUUID;
    static dispatch_once_t t;
    dispatch_once(&t, ^{
        zeroUUID = [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
    });
    return zeroUUID;
}

static void installAdSupportHookIfLoaded(void) {
    Class cls = NSClassFromString(@"ASIdentifierManager");
    if (cls) {
        hookInstanceMethod(cls, NSSelectorFromString(@"advertisingIdentifier"),
                           (IMP)my_advertisingIdentifier, (IMP *)&orig_advertisingIdentifier);
    }
}
#endif

#pragma mark - 2. App Group File Redirection (NSFileManager)

#if LC_ENABLE_SWIZZLE
static NSURL *(*orig_containerURLForGroup)(id, SEL, NSString *);
static NSURL *my_containerURLForGroup(id self, SEL _cmd, NSString *gid) {
    if (!gid.length) return orig_containerURLForGroup(self, _cmd, gid);
    NSString *base = [[NSHomeDirectory() stringByAppendingPathComponent:@"Library/LCAppGroups"]
                      stringByAppendingPathComponent:gid];
    [self createDirectoryAtPath:base withIntermediateDirectories:YES attributes:nil error:nil];
    return [NSURL fileURLWithPath:base isDirectory:YES];
}
#endif

#pragma mark - 3. Selective NSUserDefaults (6 domain methods + canary check) & CFPreferences*

#if LC_ISOLATE_PREFS
static __thread BOOL tInPrefs = NO;
// 0 = persistentDomainForName:bid mengarah ke host & suite backing tidak dikenal (merge dictRep + scoped)
// 1 = persistentDomainForName:bid sudah terikat ke guest oleh LiveContainer
// 2 = standardUserDefaults diback oleh persistent domain cid/LCDataUUID (merge cid + scoped)
static int gStdDomainMode = -1;

static BOOL isSystemOrAlreadyScopedDomain(NSString *name) {
    if (![name isKindOfClass:[NSString class]] || !name.length) return YES;
    if ([name isEqualToString:NSGlobalDomain] ||
        [name isEqualToString:NSArgumentDomain] ||
        [name isEqualToString:NSRegistrationDomain]) return YES;
    if ([name hasPrefix:@"com.apple."] ||
        [name hasPrefix:@"Apple"] ||
        [name hasPrefix:@".GlobalPreferences"]) return YES;
    if ([name hasPrefix:@"lc."]) return YES;
    // Jangan double-scope jika LiveContainer sendiri membuka suite bernama LCDataUUID / containerID.
    NSString *cid = getContainerID();
    if (cid.length && [name isEqualToString:cid]) return YES;
    return NO;
}

static BOOL isMainBundleID(NSString *name) {
    NSString *bid = [NSBundle mainBundle].bundleIdentifier;
    return (bid.length && [name isEqualToString:bid]);
}

// Untuk suite/remove/set eksplisit: bundle ID utama ("com.go-jek.gopay") TETAP di-scope!
// Memperbaiki celah v10 pada FirebaseRemoteConfig (userDefaultsSuiteNameForBundleIdentifier:) & GoPay.
static BOOL shouldScopeDomain(NSString *name, BOOL allowBundleID) {
    if (isSystemOrAlreadyScopedDomain(name)) return NO;
    if (!allowBundleID && isMainBundleID(name)) return NO;
    return YES;
}

static NSString *scopedDomain(NSString *name) {
    if (isMainBundleID(name)) {
        return [NSString stringWithFormat:@"lc.%@.app", getContainerID()];
    }
    return [NSString stringWithFormat:@"lc.%@.%@", getContainerID(), name];
}

static id (*orig_udInitWithSuiteName)(id, SEL, NSString *);
static void (*orig_udAddSuite)(id, SEL, NSString *);
static void (*orig_udRemoveSuite)(id, SEL, NSString *);
static NSDictionary *(*orig_udPersistentDomain)(id, SEL, NSString *);
static void (*orig_udSetPersistentDomain)(id, SEL, NSDictionary *, NSString *);
static void (*orig_udRemovePersistentDomain)(id, SEL, NSString *);

// Canary probe thread-safe (dispatch_once): cek bagaimana LiveContainer mengikat standardUserDefaults.
// Penting agar shared_preferences_foundation (LegacyUserDefaultsApi.getAll) tetap 100% konsisten
// tanpa pernah membaca domain host com.go-jek.gopay dan tanpa menyembunyikan key flutter.*!
static int detectStandardPersistentDomainMode(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *bid = [NSBundle mainBundle].bundleIdentifier;
        NSString *cid = getContainerID();
        if (!bid.length || !orig_udPersistentDomain) {
            gStdDomainMode = 0;
            return;
        }
        BOOL prev = tInPrefs;
        tInPrefs = YES;
        NSUserDefaults *std = [NSUserDefaults standardUserDefaults];
        NSString *probeKey = [NSString stringWithFormat:@"_lc_dom_probe_%@", cid];
        [std setObject:@"1" forKey:probeKey];
        NSDictionary *domBid = orig_udPersistentDomain(std, @selector(persistentDomainForName:), bid);
        if ([domBid[probeKey] isEqual:@"1"]) {
            gStdDomainMode = 1;
        } else {
            NSDictionary *domCid = cid.length
                ? orig_udPersistentDomain(std, @selector(persistentDomainForName:), cid)
                : nil;
            gStdDomainMode = [domCid[probeKey] isEqual:@"1"] ? 2 : 0;
        }
        [std removeObjectForKey:probeKey];
        tInPrefs = prev;
        LCLog(@"NSUserDefaults persistentDomain(%@) mode=%d (1=guestBid, 2=guestCID, 0=fallbackMerge)",
              bid, gStdDomainMode);
    });
    return gStdDomainMode;
}

static id my_udInitWithSuiteName(id self, SEL _cmd, NSString *suiteName) {
    if (tInPrefs || tInInternalIO || !shouldScopeDomain(suiteName, YES)) {
        return orig_udInitWithSuiteName(self, _cmd, suiteName);
    }
    tInPrefs = YES;
    NSString *sc = scopedDomain(suiteName);
    id r = orig_udInitWithSuiteName(self, _cmd, sc);
    tInPrefs = NO;
    return r;
}

static void my_udAddSuite(id self, SEL _cmd, NSString *suiteName) {
    if (tInPrefs || tInInternalIO || !shouldScopeDomain(suiteName, YES)) {
        orig_udAddSuite(self, _cmd, suiteName);
        return;
    }
    tInPrefs = YES;
    orig_udAddSuite(self, _cmd, scopedDomain(suiteName));
    tInPrefs = NO;
}

static void my_udRemoveSuite(id self, SEL _cmd, NSString *suiteName) {
    if (tInPrefs || tInInternalIO || !shouldScopeDomain(suiteName, YES)) {
        orig_udRemoveSuite(self, _cmd, suiteName);
        return;
    }
    tInPrefs = YES;
    orig_udRemoveSuite(self, _cmd, scopedDomain(suiteName));
    tInPrefs = NO;
}

static NSDictionary *my_udPersistentDomain(id self, SEL _cmd, NSString *domainName) {
    if (tInPrefs || tInInternalIO) {
        return orig_udPersistentDomain(self, _cmd, domainName);
    }
    // Ghidra (shared_preferences_foundation FUN_0000bbd8 + FUN_00009f08): SharedPreferencesPlugin membuat
    // [[NSUserDefaults alloc] initWithSuiteName:nil] (instance BARU, bukan pointer standardUserDefaults) lalu
    // memanggil persistentDomainForName:bundleIdentifier. Karena itu guard berlaku untuk SEMUA instance.
    if (isMainBundleID(domainName)) {
        int mode = detectStandardPersistentDomainMode();
        if (mode == 1) {
            return orig_udPersistentDomain(self, _cmd, domainName);
        }
        // LiveContainer mengisolasi standardUserDefaults via suite/file terpisah (mis. LCDataUUID),
        // sehingga persistentDomainForName:bid mengarah ke host -> gabungkan backing guest + scoped!
        tInPrefs = YES;
        NSMutableDictionary *merged = [NSMutableDictionary dictionary];
        if (mode == 2) {
            NSDictionary *cidDom = orig_udPersistentDomain(self, _cmd, getContainerID());
            if (cidDom.count) [merged addEntriesFromDictionary:cidDom];
        } else {
            NSDictionary *rep = [self dictionaryRepresentation];
            if (rep.count) [merged addEntriesFromDictionary:rep];
        }
        NSDictionary *scoped = orig_udPersistentDomain(self, _cmd, scopedDomain(domainName));
        if (scoped.count) [merged addEntriesFromDictionary:scoped];
        tInPrefs = NO;
        return merged.count ? [merged copy] : nil;
    }
    if (!shouldScopeDomain(domainName, YES)) {
        return orig_udPersistentDomain(self, _cmd, domainName);
    }
    tInPrefs = YES;
    NSDictionary *r = orig_udPersistentDomain(self, _cmd, scopedDomain(domainName));
    tInPrefs = NO;
    return r;
}

static void my_udSetPersistentDomain(id self, SEL _cmd, NSDictionary *domain, NSString *domainName) {
    if (tInPrefs || tInInternalIO || !shouldScopeDomain(domainName, YES)) {
        orig_udSetPersistentDomain(self, _cmd, domain, domainName);
        return;
    }
    tInPrefs = YES;
    orig_udSetPersistentDomain(self, _cmd, domain, scopedDomain(domainName));
    tInPrefs = NO;
}

static void my_udRemovePersistentDomain(id self, SEL _cmd, NSString *domainName) {
    if (tInPrefs || tInInternalIO || !shouldScopeDomain(domainName, YES)) {
        orig_udRemovePersistentDomain(self, _cmd, domainName);
        return;
    }
    tInPrefs = YES;
    orig_udRemovePersistentDomain(self, _cmd, scopedDomain(domainName));
    tInPrefs = NO;
}

// ---- C-API CFPreferences* (dipakai oleh APMUserDefaults di GoPay main binary) ----
// CRITICAL FIX v11: kCFPreferencesCurrentApplication & bundleID ("com.go-jek.gopay")
// SEKARANG ikut di-scope ke "lc.<cid>.app" agar APMUserDefaults tidak bocor ke host cfprefsd!
static CFPropertyListRef (*orig_CFPreferencesCopyAppValue)(CFStringRef, CFStringRef);
static void (*orig_CFPreferencesSetAppValue)(CFStringRef, CFPropertyListRef, CFStringRef);
static CFArrayRef (*orig_CFPreferencesCopyKeyList)(CFStringRef, CFStringRef, CFStringRef);
static void (*orig_CFPreferencesSetMultiple)(CFDictionaryRef, CFArrayRef, CFStringRef, CFStringRef, CFStringRef);
static Boolean (*orig_CFPreferencesAppSynchronize)(CFStringRef);
static void (*orig_CFPreferencesRemoveSuitePreferencesFromApp)(CFStringRef, CFStringRef);

static NSString *maybeScopeCFAppID(CFStringRef appID) {
    if (!appID || CFEqual(appID, kCFPreferencesAnyApplication)) {
        return nil;
    }
    if (CFEqual(appID, kCFPreferencesCurrentApplication)) {
        return [NSString stringWithFormat:@"lc.%@.app", getContainerID()];
    }
    NSString *s = (__bridge NSString *)appID;
    return shouldScopeDomain(s, YES) ? scopedDomain(s) : nil;
}

static CFPropertyListRef my_CFPreferencesCopyAppValue(CFStringRef key, CFStringRef appID) {
    if (tInPrefs || tInInternalIO) return orig_CFPreferencesCopyAppValue(key, appID);
    @autoreleasepool {
        tInPrefs = YES;
        NSString *sc = maybeScopeCFAppID(appID);
        CFPropertyListRef r = orig_CFPreferencesCopyAppValue(key, sc ? (__bridge CFStringRef)sc : appID);
        tInPrefs = NO;
        return r;
    }
}

static void my_CFPreferencesSetAppValue(CFStringRef key, CFPropertyListRef value, CFStringRef appID) {
    if (tInPrefs || tInInternalIO) { orig_CFPreferencesSetAppValue(key, value, appID); return; }
    @autoreleasepool {
        tInPrefs = YES;
        NSString *sc = maybeScopeCFAppID(appID);
        orig_CFPreferencesSetAppValue(key, value, sc ? (__bridge CFStringRef)sc : appID);
        tInPrefs = NO;
    }
}

static CFArrayRef my_CFPreferencesCopyKeyList(CFStringRef appID, CFStringRef userName, CFStringRef hostName) {
    if (tInPrefs || tInInternalIO) return orig_CFPreferencesCopyKeyList(appID, userName, hostName);
    @autoreleasepool {
        tInPrefs = YES;
        NSString *sc = maybeScopeCFAppID(appID);
        CFArrayRef r = orig_CFPreferencesCopyKeyList(sc ? (__bridge CFStringRef)sc : appID, userName, hostName);
        tInPrefs = NO;
        return r;
    }
}

static void my_CFPreferencesSetMultiple(CFDictionaryRef keysToSet, CFArrayRef keysToRemove,
                                        CFStringRef appID, CFStringRef userName, CFStringRef hostName) {
    if (tInPrefs || tInInternalIO) {
        orig_CFPreferencesSetMultiple(keysToSet, keysToRemove, appID, userName, hostName);
        return;
    }
    @autoreleasepool {
        tInPrefs = YES;
        NSString *sc = maybeScopeCFAppID(appID);
        orig_CFPreferencesSetMultiple(keysToSet, keysToRemove, sc ? (__bridge CFStringRef)sc : appID, userName, hostName);
        tInPrefs = NO;
    }
}

static Boolean my_CFPreferencesAppSynchronize(CFStringRef appID) {
    if (tInPrefs || tInInternalIO) return orig_CFPreferencesAppSynchronize(appID);
    @autoreleasepool {
        tInPrefs = YES;
        NSString *sc = maybeScopeCFAppID(appID);
        Boolean r = orig_CFPreferencesAppSynchronize(sc ? (__bridge CFStringRef)sc : appID);
        tInPrefs = NO;
        return r;
    }
}

static void my_CFPreferencesRemoveSuitePreferencesFromApp(CFStringRef appID, CFStringRef suiteID) {
    if (tInPrefs || tInInternalIO) {
        orig_CFPreferencesRemoveSuitePreferencesFromApp(appID, suiteID);
        return;
    }
    @autoreleasepool {
        tInPrefs = YES;
        NSString *scApp = maybeScopeCFAppID(appID);
        NSString *scSuite = maybeScopeCFAppID(suiteID);
        orig_CFPreferencesRemoveSuitePreferencesFromApp(scApp ? (__bridge CFStringRef)scApp : appID,
                                                      scSuite ? (__bridge CFStringRef)scSuite : suiteID);
        tInPrefs = NO;
    }
}
#endif

#pragma mark - 4. Cookies, URLCache, URLCredentialStorage, URLSession (shared/default/bg), & 5 WebView Engines

#if LC_ISOLATE_WEB_NET
static __thread BOOL tInNetIso = NO;
static NSObject *gNetLock;
static NSHTTPCookieStorage *gIsoCookieStorage;
static NSString *gIsoCookieCID;
static id gIsoCookieObserver;
static dispatch_queue_t gCookieSaveQueue;
static const void *kCookieSaveQueueKey = &kCookieSaveQueueKey;
static BOOL gCookieSaveScheduled = NO;

static NSURLCache *gIsoURLCache;
static NSString *gIsoCacheCID;
static NSURLCredentialStorage *gIsoCredStorage;
static NSString *gIsoCredCID;
static NSURLSession *gIsoSharedSession;
static NSString *gIsoSharedSessionCID;

static NSString *cookieStoreFilePath(void) {
    NSString *dir = libPath(@"Cookies");
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES attributes:nil error:nil];
    return [dir stringByAppendingPathComponent:
            [NSString stringWithFormat:@"lc_cookies_%@.bplist", getContainerID()]];
}

static NSDictionary *plistSafeCookieProps(NSDictionary *src) {
    if (![src isKindOfClass:[NSDictionary class]]) return nil;
    NSMutableDictionary *out = [NSMutableDictionary dictionaryWithCapacity:src.count];
    [src enumerateKeysAndObjectsUsingBlock:^(id k, id v, BOOL *stop) {
        (void)stop;
        if (![k isKindOfClass:[NSString class]]) return;
        if ([v isKindOfClass:[NSURL class]]) {
            NSString *abs = [(NSURL *)v absoluteString];
            if (abs.length) out[k] = abs;
        } else if ([v isKindOfClass:[NSString class]] ||
                   [v isKindOfClass:[NSNumber class]] ||
                   [v isKindOfClass:[NSDate class]] ||
                   [v isKindOfClass:[NSData class]]) {
            out[k] = v;
        } else if ([v isKindOfClass:[NSArray class]]) {
            NSMutableArray *a = [NSMutableArray array];
            for (id e in (NSArray *)v) {
                if ([e isKindOfClass:[NSString class]] || [e isKindOfClass:[NSNumber class]]) [a addObject:e];
            }
            if (a.count) out[k] = a;
        }
    }];
    return out.count ? out : nil;
}

static void persistIsolatedCookiesOnQueue(void) {
    NSHTTPCookieStorage *store = nil;
    @synchronized (gNetLock) { store = gIsoCookieStorage; }
    if (!store) return;

    NSArray<NSHTTPCookie *> *cookies = [store.cookies copy];
    NSMutableArray *props = [NSMutableArray arrayWithCapacity:cookies.count];
    NSDate *now = [NSDate date];
    for (NSHTTPCookie *c in cookies) {
        if (c.isSessionOnly) continue;
        if (c.expiresDate && [c.expiresDate compare:now] != NSOrderedDescending) continue;
        NSDictionary *safe = plistSafeCookieProps(c.properties);
        if (safe) [props addObject:safe];
    }
    NSError *err = nil;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:props
                                                              format:NSPropertyListBinaryFormat_v1_0
                                                             options:0
                                                               error:&err];
    if (data) {
        [data writeToFile:cookieStoreFilePath()
                  options:(NSDataWritingAtomic | NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication)
                    error:nil];
    } else if (err) {
        LCLog(@"WARN gagal serialize cookies: %@", err.localizedDescription);
    }
}

static void persistIsolatedCookiesNow(void) {
    if (!gCookieSaveQueue) return;
    if (dispatch_get_specific(kCookieSaveQueueKey) == kCookieSaveQueueKey) {
        persistIsolatedCookiesOnQueue();
    } else {
        dispatch_sync(gCookieSaveQueue, ^{
            persistIsolatedCookiesOnQueue();
        });
    }
}

static void scheduleCookieSave(void) {
    if (!gCookieSaveQueue) return;
    dispatch_async(gCookieSaveQueue, ^{
        if (gCookieSaveScheduled) return;
        gCookieSaveScheduled = YES;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), gCookieSaveQueue, ^{
            gCookieSaveScheduled = NO;
            persistIsolatedCookiesOnQueue();
        });
    });
}

// Memakai ephemeralSessionConfiguration.HTTPCookieStorage -> instance NSHTTPCookieStorage ASLI
// dengan CFHTTPCookieStorageRef privat (100% public API, kompatibel penuh dengan CFNetwork/NSURLSession/
// NebulaWK PSDXMLHTTPREQUESTMESSAGE/WVWKCookieUtil/IAPMarketing/flutter_inappwebview_ios).
static NSHTTPCookieStorage *isolatedCookieStorage(void) {
    NSString *cid = getContainerID();
    @synchronized (gNetLock) {
        if (gIsoCookieStorage && [gIsoCookieCID isEqualToString:cid]) return gIsoCookieStorage;
        BOOL prev = tInNetIso;
        tInNetIso = YES;

        NSURLSessionConfiguration *eph = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        NSHTTPCookieStorage *store = eph.HTTPCookieStorage;
        store.cookieAcceptPolicy = NSHTTPCookieAcceptPolicyAlways;

        NSData *raw = [NSData dataWithContentsOfFile:cookieStoreFilePath()];
        if (raw.length) {
            id list = [NSPropertyListSerialization propertyListWithData:raw options:0 format:NULL error:nil];
            if ([list isKindOfClass:[NSArray class]]) {
                NSDate *now = [NSDate date];
                for (id d in (NSArray *)list) {
                    if (![d isKindOfClass:[NSDictionary class]]) continue;
                    NSHTTPCookie *c = [NSHTTPCookie cookieWithProperties:d];
                    if (c && (!c.expiresDate || [c.expiresDate compare:now] == NSOrderedDescending)) {
                        [store setCookie:c];
                    }
                }
            }
        }

        if (!gCookieSaveQueue) {
            gCookieSaveQueue = dispatch_queue_create("com.lcisolator.cookiesave", DISPATCH_QUEUE_SERIAL);
            dispatch_queue_set_specific(gCookieSaveQueue, kCookieSaveQueueKey, (void *)kCookieSaveQueueKey, NULL);
        }
        if (gIsoCookieObserver) {
            [[NSNotificationCenter defaultCenter] removeObserver:gIsoCookieObserver];
            gIsoCookieObserver = nil;
        }
        gIsoCookieObserver = [[NSNotificationCenter defaultCenter]
                              addObserverForName:NSHTTPCookieManagerCookiesChangedNotification
                                          object:store
                                           queue:nil
                                      usingBlock:^(NSNotification *n) {
            (void)n;
            scheduleCookieSave();
        }];

        gIsoCookieStorage = store;
        gIsoCookieCID = [cid copy];
        tInNetIso = prev;
        LCLog(@"NSHTTPCookieStorage ISOLATED (%lu cookies dimuat)", (unsigned long)store.cookies.count);
        return gIsoCookieStorage;
    }
}

static NSURLCache *isolatedURLCache(void) {
    NSString *cid = getContainerID();
    @synchronized (gNetLock) {
        if (gIsoURLCache && [gIsoCacheCID isEqualToString:cid]) return gIsoURLCache;
        NSString *dir = libPath([NSString stringWithFormat:@"Caches/lc_urlcache_%@", cid]);
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        NSURL *u = [NSURL fileURLWithPath:dir isDirectory:YES];
        gIsoURLCache = [[NSURLCache alloc] initWithMemoryCapacity:(16 * 1024 * 1024)
                                                     diskCapacity:(64 * 1024 * 1024)
                                                     directoryURL:u];
        gIsoCacheCID = [cid copy];
        LCLog(@"NSURLCache ISOLATED -> %@", dir.lastPathComponent);
        return gIsoURLCache;
    }
}

static NSURLCredentialStorage *isolatedCredentialStorage(void) {
    NSString *cid = getContainerID();
    @synchronized (gNetLock) {
        if (gIsoCredStorage && [gIsoCredCID isEqualToString:cid]) return gIsoCredStorage;
        BOOL prev = tInNetIso;
        tInNetIso = YES;
        gIsoCredStorage = [NSURLSessionConfiguration ephemeralSessionConfiguration].URLCredentialStorage;
        gIsoCredCID = [cid copy];
        tInNetIso = prev;
        LCLog(@"NSURLCredentialStorage ISOLATED");
        return gIsoCredStorage;
    }
}

static NSHTTPCookieStorage *(*orig_sharedHTTPCookieStorage)(id, SEL);
static NSHTTPCookieStorage *my_sharedHTTPCookieStorage(id self, SEL _cmd) {
    if (tInNetIso) return orig_sharedHTTPCookieStorage(self, _cmd);
    return isolatedCookieStorage() ?: orig_sharedHTTPCookieStorage(self, _cmd);
}

static NSHTTPCookieStorage *(*orig_sharedCookieStorageForGroup)(id, SEL, NSString *);
static NSHTTPCookieStorage *my_sharedCookieStorageForGroup(id self, SEL _cmd, NSString *gid) {
    (void)gid;
    if (tInNetIso) return orig_sharedCookieStorageForGroup(self, _cmd, gid);
    return isolatedCookieStorage() ?: orig_sharedCookieStorageForGroup(self, _cmd, gid);
}

static NSURLCache *(*orig_sharedURLCache)(id, SEL);
static NSURLCache *my_sharedURLCache(id self, SEL _cmd) {
    if (tInNetIso) return orig_sharedURLCache(self, _cmd);
    return isolatedURLCache() ?: orig_sharedURLCache(self, _cmd);
}

// Proteksi v11: jangan izinkan caller menimpa gIsoURLCache dengan cache ber-diskPath host;
// cukup salin kapasitasnya ke gIsoURLCache milik container!
static void (*orig_setSharedURLCache)(id, SEL, NSURLCache *);
static void my_setSharedURLCache(id self, SEL _cmd, NSURLCache *cache) {
    (void)self; (void)_cmd;
    if (!cache) return;
    NSURLCache *iso = isolatedURLCache();
    if (iso && cache != iso) {
        iso.memoryCapacity = cache.memoryCapacity;
        iso.diskCapacity = cache.diskCapacity;
        LCLog(@"NSURLCache setSharedURLCache kapasitas disesuaikan (mem=%lu disk=%lu)",
              (unsigned long)cache.memoryCapacity, (unsigned long)cache.diskCapacity);
    }
}

static NSURLCredentialStorage *(*orig_sharedCredentialStorage)(id, SEL);
static NSURLCredentialStorage *my_sharedCredentialStorage(id self, SEL _cmd) {
    if (tInNetIso) return orig_sharedCredentialStorage(self, _cmd);
    return isolatedCredentialStorage() ?: orig_sharedCredentialStorage(self, _cmd);
}

static NSURLSessionConfiguration *(*orig_defaultSessionConfig)(id, SEL);
static NSURLSessionConfiguration *my_defaultSessionConfig(id self, SEL _cmd) {
    NSURLSessionConfiguration *cfg = orig_defaultSessionConfig(self, _cmd);
    if (!tInNetIso && cfg) {
        tInNetIso = YES;
        cfg.HTTPCookieStorage = isolatedCookieStorage();
        cfg.URLCache = isolatedURLCache();
        cfg.URLCredentialStorage = isolatedCredentialStorage();
        tInNetIso = NO;
    }
    return cfg;
}

// CRITICAL FIX v11: Isolasi +[NSURLSession sharedSession] yang dipakai langsung oleh 8 biner
// (GoPay, GotoNetworking, tagihan_unified_emoney [BCA Flazz/KMT], AppAuth, NaradSDK, Firebase*).
static NSURLSession *(*orig_sharedSession)(id, SEL);
static NSURLSession *isolatedSharedSession(void) {
    NSString *cid = getContainerID();
    @synchronized (gNetLock) {
        if (gIsoSharedSession && [gIsoSharedSessionCID isEqualToString:cid]) return gIsoSharedSession;
        BOOL prev = tInNetIso;
        tInNetIso = YES;
        NSURLSessionConfiguration *cfg = orig_defaultSessionConfig
            ? orig_defaultSessionConfig([NSURLSessionConfiguration class], @selector(defaultSessionConfiguration))
            : [NSURLSessionConfiguration defaultSessionConfiguration];
        cfg.HTTPCookieStorage = isolatedCookieStorage();
        cfg.URLCache = isolatedURLCache();
        cfg.URLCredentialStorage = isolatedCredentialStorage();
        gIsoSharedSession = [NSURLSession sessionWithConfiguration:cfg];
        gIsoSharedSessionCID = [cid copy];
        tInNetIso = prev;
        LCLog(@"NSURLSession.sharedSession ISOLATED (cid=%@)", cid);
        return gIsoSharedSession;
    }
}

static NSURLSession *my_sharedSession(id self, SEL _cmd) {
    if (tInNetIso) return orig_sharedSession(self, _cmd);
    return isolatedSharedSession() ?: orig_sharedSession(self, _cmd);
}

// Isolasi background URLSession agar tidak tabrakan di daemon nsurlsessiond
// (dipakai GoPay, GoogleUtilities com.gul.network.background-upload, GTMSessionFetcher).
// FIX v11: jangan memasang ephemeral cookie/credential store ke background session out-of-process,
// dan bersihkan sharedContainerIdentifier agar tidak konflik App Group.
// Ghidra: GULNetworkURLSession::handleEventsForBackgroundURLSessionID: (0xc4ec) & fetcherWithSessionIdentifier:
// (0xde30) memakai [sessionID hasPrefix:kGULNetworkBackgroundSessionConfigIDPrefix]; GTMSessionFetcher juga
// memakai hasPrefix:. Karena itu marker container dipasang sebagai SUFFIX (bukan prefix) agar hasPrefix tetap cocok,
// dan suffix dilepas kembali saat iOS mengirim application:handleEventsForBackgroundURLSession: ke AppDelegate.
static NSString *bgIdentifierSuffix(void) {
    return [NSString stringWithFormat:@".lcbg-%@", getContainerID()];
}

static NSString *scopeBackgroundIdentifier(NSString *identifier) {
    if (!identifier.length) return identifier;
    NSString *sfx = bgIdentifierSuffix();
    if ([identifier hasSuffix:sfx]) return identifier;
    return [identifier stringByAppendingString:sfx];
}

static NSString *unscopeBackgroundIdentifier(NSString *identifier) {
    if (![identifier isKindOfClass:[NSString class]]) return identifier;
    NSString *sfx = bgIdentifierSuffix();
    if ([identifier hasSuffix:sfx] && identifier.length > sfx.length) {
        return [identifier substringToIndex:identifier.length - sfx.length];
    }
    return identifier;
}

static void (*orig_appHandleBgEvents)(id, SEL, UIApplication *, NSString *, void (^)(void));
static void my_appHandleBgEvents(id self, SEL _cmd, UIApplication *app, NSString *identifier, void (^completion)(void)) {
    NSString *mine = unscopeBackgroundIdentifier(identifier);
    if (identifier.length && mine == identifier) {
        // Event milik container lain (atau tanpa marker) -> jangan diteruskan ke SDK container ini.
        NSString *sfxRoot = @".lcbg-";
        if ([identifier rangeOfString:sfxRoot].location != NSNotFound) {
            LCLog(@"bg URLSession event container lain diabaikan");
            if (completion) completion();
            return;
        }
    }
    orig_appHandleBgEvents(self, _cmd, app, mine, completion);
}

static void installAppDelegateBgHookIfReady(void) {
    static BOOL done = NO;
    if (done) return;
    id<UIApplicationDelegate> d = [UIApplication sharedApplication].delegate;
    if (!d) return;
    SEL sel = @selector(application:handleEventsForBackgroundURLSession:completionHandler:);
    Class cls = [d class];
    if (class_getInstanceMethod(cls, sel)) {
        hookInstanceMethod(cls, sel, (IMP)my_appHandleBgEvents, (IMP *)&orig_appHandleBgEvents);
    }
    done = YES;
}

static NSURLSessionConfiguration *(*orig_bgSessionConfig)(id, SEL, NSString *);
static NSURLSessionConfiguration *my_bgSessionConfig(id self, SEL _cmd, NSString *identifier) {
    NSString *scoped = scopeBackgroundIdentifier(identifier);
    NSURLSessionConfiguration *cfg = orig_bgSessionConfig(self, _cmd, scoped);
    if (cfg) {
        cfg.sharedContainerIdentifier = nil;
    }
    return cfg;
}

// Variant deprecated masih direferensikan di GoPay main binary.
static NSURLSessionConfiguration *(*orig_bgSessionConfigLegacy)(id, SEL, NSString *);
static NSURLSessionConfiguration *my_bgSessionConfigLegacy(id self, SEL _cmd, NSString *identifier) {
    NSString *scoped = scopeBackgroundIdentifier(identifier);
    NSURLSessionConfiguration *cfg = orig_bgSessionConfigLegacy(self, _cmd, scoped);
    if (cfg) {
        cfg.sharedContainerIdentifier = nil;
    }
    return cfg;
}

// ---- WKWebsiteDataStore + WKWebViewConfiguration + WKWebView + WKContentRuleListStore ----
static WKWebsiteDataStore *gIsoWKStore;
static NSString *gIsoWKCID;
#if LC_WEBVIEW_IOS16_ISOLATE
static WKHTTPCookieStore *gIsoWKCookieStore;
#endif
static WKContentRuleListStore *gIsoRuleListStore;
static NSString *gIsoRuleListCID;
static __thread BOOL tInWKInit = NO;

static WKWebsiteDataStore *(*orig_wkDefaultDataStore)(id, SEL);

#if LC_WEBVIEW_IOS16_ISOLATE
static void hydrateWKStoreCookiesOnIOS16(WKWebsiteDataStore *store) {
    if (!store) return;
    NSArray<NSHTTPCookie *> *cookies = [isolatedCookieStorage().cookies copy];
    if (!cookies.count) return;
    WKHTTPCookieStore *wkcs = store.httpCookieStore;
    for (NSHTTPCookie *c in cookies) {
        [wkcs setCookie:c completionHandler:nil];
    }
    LCLog(@"WKWebsiteDataStore(iOS<17) hydrate %lu cookies dari container", (unsigned long)cookies.count);
}
#endif

static WKWebsiteDataStore *isolatedStore(void) {
    NSString *cid = getContainerID();
    if (gIsoWKStore && [gIsoWKCID isEqualToString:cid]) return gIsoWKStore;
    void (^make)(void) = ^{
        if (gIsoWKStore && [gIsoWKCID isEqualToString:cid]) return;
        BOOL prev = tInWKInit;
        tInWKInit = YES;
        if (@available(iOS 17.0, *)) {
            gIsoWKStore = [WKWebsiteDataStore dataStoreForIdentifier:uuidFromString(cid)];
            LCLog(@"WKWebsiteDataStore: ISOLATED (iOS 17+ persistent uuid)");
        } else {
#if LC_WEBVIEW_IOS16_ISOLATE
            gIsoWKStore = [WKWebsiteDataStore nonPersistentDataStore];
            gIsoWKCookieStore = gIsoWKStore.httpCookieStore;
            hydrateWKStoreCookiesOnIOS16(gIsoWKStore);
            LCLog(@"WKWebsiteDataStore: ISOLATED (iOS <17 nonPersistent + cookie sync)");
#else
            LCLog(@"WKWebsiteDataStore: TIDAK terisolasi (iOS <17, LC_WEBVIEW_IOS16_ISOLATE=0)");
#endif
        }
        gIsoWKCID = [cid copy];
        tInWKInit = prev;
    };
    if ([NSThread isMainThread]) make();
    else dispatch_sync(dispatch_get_main_queue(), make);
    return gIsoWKStore;
}

static WKWebsiteDataStore *my_wkDefaultDataStore(id self, SEL _cmd) {
    if (tInWKInit) return orig_wkDefaultDataStore(self, _cmd);
    tInWKInit = YES;
    WKWebsiteDataStore *iso = isolatedStore();
    tInWKInit = NO;
    return iso ?: orig_wkDefaultDataStore(self, _cmd);
}

// CRITICAL FIX v11 (W3): Isolasi WKContentRuleListStore.defaultStore (dipakai flutter_inappwebview_ios contentBlockers).
static WKContentRuleListStore *(*orig_wkRuleListDefaultStore)(id, SEL);
static WKContentRuleListStore *isolatedRuleListStore(void) {
    NSString *cid = getContainerID();
    if (gIsoRuleListStore && [gIsoRuleListCID isEqualToString:cid]) return gIsoRuleListStore;
    void (^make)(void) = ^{
        if (gIsoRuleListStore && [gIsoRuleListCID isEqualToString:cid]) return;
        NSString *dir = libPath([NSString stringWithFormat:@"WebKit/LCContentRuleLists_%@", cid]);
        [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        NSURL *u = [NSURL fileURLWithPath:dir isDirectory:YES];
        gIsoRuleListStore = [WKContentRuleListStore storeWithURL:u];
        gIsoRuleListCID = [cid copy];
        LCLog(@"WKContentRuleListStore ISOLATED -> %@", dir.lastPathComponent);
    };
    if ([NSThread isMainThread]) make();
    else dispatch_sync(dispatch_get_main_queue(), make);
    return gIsoRuleListStore;
}

static WKContentRuleListStore *my_wkRuleListDefaultStore(id self, SEL _cmd) {
    if (tInWKInit) return orig_wkRuleListDefaultStore(self, _cmd);
    tInWKInit = YES;
    WKContentRuleListStore *iso = isolatedRuleListStore();
    tInWKInit = NO;
    return iso ?: orig_wkRuleListDefaultStore(self, _cmd);
}

// Deteksi popup window.open / target="_blank" / 3DS / onCreateWindow (createWebViewWithConfiguration:).
// WebKit melempar NSInvalidArgumentException jika websiteDataStore/processPool pada popup config dimutasi!
static BOOL isRelatedPopupConfig(WKWebViewConfiguration *cfg) {
    if (!cfg) return NO;
    SEL relSel = NSSelectorFromString(@"_relatedWebView");
    if ([cfg respondsToSelector:relSel]) {
        id rel = ((id (*)(id, SEL))objc_msgSend)(cfg, relSel);
        if (rel != nil) return YES;
    }
    return NO;
}

#if LC_FORCE_WEBVIEW_STORE
// Identifikasi defaultDataStore host tanpa pernah memanggil orig_wkDefaultDataStore():
// Di iOS 17+, defaultDataStore adalah satu-satunya store dengan isPersistent==YES && identifier==nil.
// Di iOS <17, tidak ada dataStoreForIdentifier:, sehingga semua store persisten adalah defaultDataStore.
static BOOL isHostDefaultWKStore(WKWebsiteDataStore *store) {
    if (!store || !store.isPersistent) return NO;
    if (@available(iOS 17.0, *)) {
        return store.identifier == nil;
    }
    return YES;
}
#endif

static void (*orig_wkCfgSetStore)(id, SEL, WKWebsiteDataStore *);
static void my_wkCfgSetStore(id self, SEL _cmd, WKWebsiteDataStore *store) {
#if LC_FORCE_WEBVIEW_STORE
    if (!tInWKInit && isHostDefaultWKStore(store) && !isRelatedPopupConfig(self)) {
        tInWKInit = YES;
        WKWebsiteDataStore *iso = isolatedStore();
        tInWKInit = NO;
        if (iso) {
            orig_wkCfgSetStore(self, _cmd, iso);
            return;
        }
    }
#endif
    orig_wkCfgSetStore(self, _cmd, store);
}

static void applyIsolatedStoreToConfigIfNeeded(WKWebViewConfiguration *cfg) {
#if LC_FORCE_WEBVIEW_STORE
    if (!cfg || isRelatedPopupConfig(cfg)) return;
    WKWebsiteDataStore *cur = cfg.websiteDataStore;
    if (cur && !cur.isPersistent) return; // hormati incognito/nonPersistent
    WKWebsiteDataStore *iso = isolatedStore();
    if (iso && cur != iso) {
        if (orig_wkCfgSetStore) orig_wkCfgSetStore(cfg, @selector(setWebsiteDataStore:), iso);
        else cfg.websiteDataStore = iso;
    }
#else
    (void)cfg;
#endif
}

// Pasang store container sejak WKWebViewConfiguration lahir (init, initWithCoder:, copyWithZone:).
// Catatan: pada iOS 15+, WKProcessPool sudah deprecated dan tidak memisahkan data lintas launch;
// tidak menimpa processPool mencegah bentrok dengan WKProcessPoolManager milik flutter_inappwebview_ios.
static id (*orig_wkCfgInit)(id, SEL);
static id my_wkCfgInit(id self, SEL _cmd) {
    WKWebViewConfiguration *cfg = orig_wkCfgInit(self, _cmd);
    if (cfg && !tInWKInit) {
        tInWKInit = YES;
        applyIsolatedStoreToConfigIfNeeded(cfg);
        tInWKInit = NO;
    }
    return cfg;
}

static id (*orig_wkCfgInitCoder)(id, SEL, NSCoder *);
static id my_wkCfgInitCoder(id self, SEL _cmd, NSCoder *coder) {
    WKWebViewConfiguration *cfg = orig_wkCfgInitCoder(self, _cmd, coder);
    if (cfg && !tInWKInit) {
        tInWKInit = YES;
        applyIsolatedStoreToConfigIfNeeded(cfg);
        tInWKInit = NO;
    }
    return cfg;
}

static id (*orig_wkCfgCopyWithZone)(id, SEL, NSZone *);
static id my_wkCfgCopyWithZone(id self, SEL _cmd, NSZone *zone) {
    WKWebViewConfiguration *copy = orig_wkCfgCopyWithZone(self, _cmd, zone);
    if (copy && !tInWKInit) {
        tInWKInit = YES;
        applyIsolatedStoreToConfigIfNeeded(copy);
        tInWKInit = NO;
    }
    return copy;
}

static _Atomic int gWKInitLogCount = 0;

static id (*orig_wkInitFrameCfg)(id, SEL, CGRect, WKWebViewConfiguration *);
static id my_wkInitFrameCfg(id self, SEL _cmd, CGRect frame, WKWebViewConfiguration *configuration) {
    WKWebsiteDataStore *iso = nil;
    if (!tInWKInit) {
        tInWKInit = YES;
        iso = isolatedStore();
        tInWKInit = NO;
    }
    NSString *state = @"ok";
    if (!configuration) {
#if LC_FORCE_WEBVIEW_STORE
        configuration = [[WKWebViewConfiguration alloc] init];
        if (iso && configuration.websiteDataStore != iso) {
            tInWKInit = YES;
            if (orig_wkCfgSetStore) orig_wkCfgSetStore(configuration, @selector(setWebsiteDataStore:), iso);
            else configuration.websiteDataStore = iso;
            tInWKInit = NO;
        }
        state = iso ? @"nil-cfg -> DIBUAT store container" : @"nil-cfg (iOS <17 off)";
#else
        state = @"nil-cfg (dibiarkan)";
#endif
    } else if (isRelatedPopupConfig(configuration)) {
        // Popup 3DS/OAuth/onCreateWindow: JANGAN ubah websiteDataStore/processPool (cegah NSInvalidArgumentException)!
        state = (iso && configuration.websiteDataStore == iso)
            ? @"popup (_relatedWebView -> sudah store container)"
            : @"popup (_relatedWebView -> dipertahankan aman)";
    } else {
        WKWebsiteDataStore *cur = configuration.websiteDataStore;
        if (!cur.isPersistent) {
            state = (iso && cur == iso) ? @"sudah store container (iOS<17)" : @"non-persisten/incognito (dibiarkan)";
        } else if (iso && cur == iso) {
            state = @"sudah store container";
        } else {
#if LC_FORCE_WEBVIEW_STORE
            if (iso) {
                tInWKInit = YES;
                if (orig_wkCfgSetStore) orig_wkCfgSetStore(configuration, @selector(setWebsiteDataStore:), iso);
                else configuration.websiteDataStore = iso;
                tInWKInit = NO;
                state = @"DIPAKSA ke store container";
            } else {
                state = @"persisten, tidak bisa dipaksa (iOS <17 off)";
            }
#else
            state = @"persisten, store bersama (LC_FORCE_WEBVIEW_STORE=0)";
#endif
        }
    }
    int c = atomic_fetch_add_explicit(&gWKInitLogCount, 1, memory_order_relaxed);
    if (c < 200) {
        LCLog(@"WKWebView init class=%@ store=%@", NSStringFromClass([self class]), state);
    }
    return orig_wkInitFrameCfg(self, _cmd, frame, configuration);
}

static id (*orig_wkInitCoder)(id, SEL, NSCoder *);
static id my_wkInitCoder(id self, SEL _cmd, NSCoder *coder) {
    WKWebView *wv = orig_wkInitCoder(self, _cmd, coder);
    if (wv) {
        BOOL isIso = (gIsoWKStore && wv.configuration.websiteDataStore == gIsoWKStore);
        LCLog(@"WKWebView initWithCoder class=%@ persistent=%d isolated=%@",
              NSStringFromClass([wv class]), (int)wv.configuration.websiteDataStore.isPersistent,
              isIso ? @"YA" : @"TIDAK");
    }
    return wv;
}
#endif

#pragma mark - 5. Browser / OAuth Isolation & Trace (ASWebAuthenticationSession, SFAuthenticationSession, SFSafariViewController)

static id (*orig_asInit)(id, SEL, NSURL *, NSString *, id);
static id my_asInit(id self, SEL _cmd, NSURL *url, NSString *scheme, id handler) {
#if LC_TRACE_WEB
    LCLog(@"ASWebAuthenticationSession %@://%@ callback=%@", url.scheme ?: @"-", url.host ?: @"-", scheme ?: @"-");
#endif
    id obj = orig_asInit(self, _cmd, url, scheme, handler);
#if LC_EPHEMERAL_WEBAUTH
    SEL ephSel = NSSelectorFromString(@"setPrefersEphemeralWebBrowserSession:");
    if (obj && [obj respondsToSelector:ephSel]) {
        ((void (*)(id, SEL, BOOL))objc_msgSend)(obj, ephSel, YES);
    }
#endif
    return obj;
}

// iOS 17.4+ API: initWithURL:callback:completionHandler:
static id (*orig_asInitCallback)(id, SEL, NSURL *, id, id);
static id my_asInitCallback(id self, SEL _cmd, NSURL *url, id callback, id handler) {
#if LC_TRACE_WEB
    LCLog(@"ASWebAuthenticationSession(iOS17.4) %@://%@", url.scheme ?: @"-", url.host ?: @"-");
#endif
    id obj = orig_asInitCallback(self, _cmd, url, callback, handler);
#if LC_EPHEMERAL_WEBAUTH
    SEL ephSel = NSSelectorFromString(@"setPrefersEphemeralWebBrowserSession:");
    if (obj && [obj respondsToSelector:ephSel]) {
        ((void (*)(id, SEL, BOOL))objc_msgSend)(obj, ephSel, YES);
    }
#endif
    return obj;
}

#if LC_EPHEMERAL_WEBAUTH
// CRITICAL FIX v11 (W1): flutter_inappwebview_ios & AppAuth memanggil setPrefersEphemeralWebBrowserSession:NO
// SETELAH init selesai! Hook setter & start() memastikan sesi OAuth tetap ephemeral!
static void (*orig_asSetEphemeral)(id, SEL, BOOL);
static void my_asSetEphemeral(id self, SEL _cmd, BOOL flag) {
    (void)flag;
#if LC_TRACE_WEB
    if (!flag) LCLog(@"ASWebAuthenticationSession setPrefersEphemeral:NO -> DIPAKSA YES");
#endif
    orig_asSetEphemeral(self, _cmd, YES);
}

static BOOL (*orig_asStart)(id, SEL);
static BOOL my_asStart(id self, SEL _cmd) {
    SEL ephSel = NSSelectorFromString(@"setPrefersEphemeralWebBrowserSession:");
    if ([self respondsToSelector:ephSel]) {
        ((void (*)(id, SEL, BOOL))objc_msgSend)(self, ephSel, YES);
    }
    return orig_asStart(self, _cmd);
}
#endif

#if LC_TRACE_WEB
static id (*orig_sfAuthInit)(id, SEL, NSURL *, NSString *, id);
static id my_sfAuthInit(id self, SEL _cmd, NSURL *url, NSString *scheme, id handler) {
    LCLog(@"SFAuthenticationSession (legacy Safari sistem!) %@://%@ callback=%@",
          url.scheme ?: @"-", url.host ?: @"-", scheme ?: @"-");
    return orig_sfAuthInit(self, _cmd, url, scheme, handler);
}

static id (*orig_sfInit)(id, SEL, NSURL *, id);
static id my_sfInit(id self, SEL _cmd, NSURL *url, id cfg) {
    LCLog(@"SFSafariViewController(cfg) %@://%@", url.scheme ?: @"-", url.host ?: @"-");
    return orig_sfInit(self, _cmd, url, cfg);
}

static id (*orig_sfInitReader)(id, SEL, NSURL *, BOOL);
static id my_sfInitReader(id self, SEL _cmd, NSURL *url, BOOL reader) {
    LCLog(@"SFSafariViewController(reader=%d) %@://%@", (int)reader, url.scheme ?: @"-", url.host ?: @"-");
    return orig_sfInitReader(self, _cmd, url, reader);
}

static id (*orig_sfPrewarm)(id, SEL, NSArray *);
static id my_sfPrewarm(id self, SEL _cmd, NSArray *urls) {
    LCLog(@"SFSafariViewController prewarmConnections count=%lu", (unsigned long)urls.count);
    return orig_sfPrewarm(self, _cmd, urls);
}

static void (*orig_sfClearWebsiteData)(id, SEL, void (^)(void));
static void my_sfClearWebsiteData(id self, SEL _cmd, void (^completion)(void)) {
    LCLog(@"SFSafariViewControllerDataStore clearWebsiteData dipanggil");
    orig_sfClearWebsiteData(self, _cmd, completion);
}

static WKNavigation *(*orig_wkLoadRequest)(id, SEL, NSURLRequest *);
static WKNavigation *my_wkLoadRequest(id self, SEL _cmd, NSURLRequest *req) {
    LCLog(@"WKWebView(%@) loadRequest %@://%@%@", NSStringFromClass([self class]),
          req.URL.scheme ?: @"-", req.URL.host ?: @"-", req.URL.path ?: @"");
    return orig_wkLoadRequest(self, _cmd, req);
}

static WKNavigation *(*orig_wkLoadHTML)(id, SEL, NSString *, NSURL *);
static WKNavigation *my_wkLoadHTML(id self, SEL _cmd, NSString *html, NSURL *baseURL) {
    LCLog(@"WKWebView(%@) loadHTMLString len=%lu base=%@://%@", NSStringFromClass([self class]),
          (unsigned long)html.length, baseURL.scheme ?: @"-", baseURL.host ?: @"-");
    return orig_wkLoadHTML(self, _cmd, html, baseURL);
}

static WKNavigation *(*orig_wkLoadFile)(id, SEL, NSURL *, NSURL *);
static WKNavigation *my_wkLoadFile(id self, SEL _cmd, NSURL *fileURL, NSURL *readAccessURL) {
    LCLog(@"WKWebView(%@) loadFileURL %@", NSStringFromClass([self class]), fileURL.lastPathComponent ?: @"-");
    return orig_wkLoadFile(self, _cmd, fileURL, readAccessURL);
}

static void (*orig_wkSetCookie)(id, SEL, NSHTTPCookie *, void (^)(void));
static void my_wkSetCookie(id self, SEL _cmd, NSHTTPCookie *cookie, void (^handler)(void)) {
    LCLog(@"WKHTTPCookieStore setCookie name=%@ domain=%@", cookie.name, cookie.domain);
#if LC_ISOLATE_WEB_NET && LC_WEBVIEW_IOS16_ISOLATE
    if (@available(iOS 17.0, *)) {
        // iOS 17+ persisten otomatis di dataStoreForIdentifier
    } else if (cookie && gIsoWKCookieStore && self == gIsoWKCookieStore) {
        [isolatedCookieStorage() setCookie:cookie];
    }
#endif
    orig_wkSetCookie(self, _cmd, cookie, handler);
}

static void (*orig_wkDeleteCookie)(id, SEL, NSHTTPCookie *, void (^)(void));
static void my_wkDeleteCookie(id self, SEL _cmd, NSHTTPCookie *cookie, void (^handler)(void)) {
    LCLog(@"WKHTTPCookieStore deleteCookie name=%@ domain=%@", cookie.name, cookie.domain);
#if LC_ISOLATE_WEB_NET && LC_WEBVIEW_IOS16_ISOLATE
    if (@available(iOS 17.0, *)) {
    } else if (cookie && gIsoWKCookieStore && self == gIsoWKCookieStore) {
        [isolatedCookieStorage() deleteCookie:cookie];
    }
#endif
    orig_wkDeleteCookie(self, _cmd, cookie, handler);
}

static void (*orig_wkRemoveDataSince)(id, SEL, NSSet<NSString *> *, NSDate *, void (^)(void));
static void my_wkRemoveDataSince(id self, SEL _cmd, NSSet<NSString *> *types, NSDate *date, void (^handler)(void)) {
#if LC_ISOLATE_WEB_NET
    BOOL isIso = (gIsoWKStore && self == gIsoWKStore);
#else
    BOOL isIso = NO;
#endif
    LCLog(@"WKWebsiteDataStore removeDataOfTypes count=%lu isolated=%@",
          (unsigned long)types.count, isIso ? @"YA" : @"TIDAK");
    orig_wkRemoveDataSince(self, _cmd, types, date, handler);
}

static void (*orig_wkAddMsgHandler)(id, SEL, id<WKScriptMessageHandler>, NSString *);
static void my_wkAddMsgHandler(id self, SEL _cmd, id<WKScriptMessageHandler> handler, NSString *name) {
    LCLog(@"WK JS message handler: %@", name);
    orig_wkAddMsgHandler(self, _cmd, handler, name);
}

static void (*orig_wkAddMsgHandlerWorld)(id, SEL, id<WKScriptMessageHandler>, id, NSString *);
static void my_wkAddMsgHandlerWorld(id self, SEL _cmd, id<WKScriptMessageHandler> handler, id world, NSString *name) {
    LCLog(@"WK JS message handler(world): %@", name);
    orig_wkAddMsgHandlerWorld(self, _cmd, handler, world, name);
}

static void (*orig_appOpenURL)(id, SEL, NSURL *, NSDictionary *, void (^)(BOOL));
static void my_appOpenURL(id self, SEL _cmd, NSURL *url, NSDictionary *options, void (^handler)(BOOL)) {
    LCLog(@"UIApplication openURL %@://%@", url.scheme ?: @"-", url.host ?: @"-");
    orig_appOpenURL(self, _cmd, url, options, handler);
}
#elif LC_ISOLATE_WEB_NET && LC_WEBVIEW_IOS16_ISOLATE
// Jika LC_TRACE_WEB=0 tapi LC_WEBVIEW_IOS16_ISOLATE=1, tetap mirror cookie iOS<17.
static void (*orig_wkSetCookie)(id, SEL, NSHTTPCookie *, void (^)(void));
static void my_wkSetCookie(id self, SEL _cmd, NSHTTPCookie *cookie, void (^handler)(void)) {
    if (@available(iOS 17.0, *)) {
    } else if (cookie && gIsoWKCookieStore && self == gIsoWKCookieStore) {
        [isolatedCookieStorage() setCookie:cookie];
    }
    orig_wkSetCookie(self, _cmd, cookie, handler);
}

static void (*orig_wkDeleteCookie)(id, SEL, NSHTTPCookie *, void (^)(void));
static void my_wkDeleteCookie(id self, SEL _cmd, NSHTTPCookie *cookie, void (^handler)(void)) {
    if (@available(iOS 17.0, *)) {
    } else if (cookie && gIsoWKCookieStore && self == gIsoWKCookieStore) {
        [isolatedCookieStorage() deleteCookie:cookie];
    }
    orig_wkDeleteCookie(self, _cmd, cookie, handler);
}
#endif

static void installBrowserHooksIfLoaded(void) {
    Class asCls = NSClassFromString(@"ASWebAuthenticationSession");
    if (asCls) {
        hookInstanceMethod(asCls,
                           NSSelectorFromString(@"initWithURL:callbackURLScheme:completionHandler:"),
                           (IMP)my_asInit, (IMP *)&orig_asInit);
        if (class_getInstanceMethod(asCls, NSSelectorFromString(@"initWithURL:callback:completionHandler:"))) {
            hookInstanceMethod(asCls,
                               NSSelectorFromString(@"initWithURL:callback:completionHandler:"),
                               (IMP)my_asInitCallback, (IMP *)&orig_asInitCallback);
        }
#if LC_EPHEMERAL_WEBAUTH
        hookInstanceMethod(asCls,
                           NSSelectorFromString(@"setPrefersEphemeralWebBrowserSession:"),
                           (IMP)my_asSetEphemeral, (IMP *)&orig_asSetEphemeral);
        hookInstanceMethod(asCls,
                           NSSelectorFromString(@"start"),
                           (IMP)my_asStart, (IMP *)&orig_asStart);
#endif
    }
#if LC_TRACE_WEB
    Class sfAuthCls = NSClassFromString(@"SFAuthenticationSession");
    if (sfAuthCls) {
        hookInstanceMethod(sfAuthCls,
                           NSSelectorFromString(@"initWithURL:callbackURLScheme:completionHandler:"),
                           (IMP)my_sfAuthInit, (IMP *)&orig_sfAuthInit);
    }
    Class sfCls = NSClassFromString(@"SFSafariViewController");
    if (sfCls) {
        hookInstanceMethod(sfCls,
                           NSSelectorFromString(@"initWithURL:configuration:"),
                           (IMP)my_sfInit, (IMP *)&orig_sfInit);
        hookInstanceMethod(sfCls,
                           NSSelectorFromString(@"initWithURL:entersReaderIfAvailable:"),
                           (IMP)my_sfInitReader, (IMP *)&orig_sfInitReader);
        if (class_getClassMethod(sfCls, NSSelectorFromString(@"prewarmConnectionsToURLs:"))) {
            hookClassMethod(sfCls,
                            NSSelectorFromString(@"prewarmConnectionsToURLs:"),
                            (IMP)my_sfPrewarm, (IMP *)&orig_sfPrewarm);
        }
    }
    Class sfDS = NSClassFromString(@"SFSafariViewControllerDataStore");
    if (sfDS) {
        hookInstanceMethod(sfDS,
                           NSSelectorFromString(@"clearWebsiteDataWithCompletionHandler:"),
                           (IMP)my_sfClearWebsiteData, (IMP *)&orig_sfClearWebsiteData);
    }
#endif
}

#pragma mark - 6. UIPasteboard Isolation (class-cluster safe + Smart Payment Mode 3)

#if LC_PASTEBOARD_MODE > 0
static NSObject *gPBLock;
static NSMutableArray<NSDictionary<NSString *, id> *> *gPBItems;
static NSInteger gPBChangeCount = 0;
static _Atomic BOOL gAppIsActive = NO;

static BOOL isGeneralPB(UIPasteboard *pb) {
    if (!pb) return NO;
    return [pb.name isEqualToString:UIPasteboardNameGeneral];
}

#if LC_PASTEBOARD_MODE == 3
static BOOL allowInteractiveGeneralPB(void) {
    return atomic_load_explicit(&gAppIsActive, memory_order_relaxed);
}
#endif

static UIPasteboard *(*orig_pbWithName)(id, SEL, UIPasteboardName, BOOL);
static UIPasteboard *my_pbWithName(id self, SEL _cmd, UIPasteboardName name, BOOL create) {
    if (name.length &&
        ![name isEqualToString:UIPasteboardNameGeneral] &&
        ![name hasPrefix:@"lc."]) {
        NSString *scoped = [NSString stringWithFormat:@"lc.%@.%@", getContainerID(), name];
        return orig_pbWithName(self, _cmd, scoped, create);
    }
    return orig_pbWithName(self, _cmd, name, create);
}

static NSString *(*orig_pbString)(id, SEL);
static NSString *my_pbString(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbString(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
    return @"";
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) return orig_pbString(self, _cmd);
    return nil;
#else
    @synchronized (gPBLock) {
        for (NSDictionary *item in gPBItems) {
            id v = item[@"public.utf8-plain-text"] ?: item[@"public.text"];
            if ([v isKindOfClass:[NSString class]]) return v;
            if ([v isKindOfClass:[NSData class]]) {
                return [[NSString alloc] initWithData:v encoding:NSUTF8StringEncoding];
            }
        }
        return nil;
    }
#endif
}

static void (*orig_pbSetString)(id, SEL, NSString *);
static void my_pbSetString(id self, SEL _cmd, NSString *s) {
    if (!isGeneralPB(self)) { orig_pbSetString(self, _cmd, s); return; }
#if LC_PASTEBOARD_MODE == 1
    @synchronized (gPBLock) {
        [gPBItems removeAllObjects];
        if (s) [gPBItems addObject:@{ @"public.utf8-plain-text": [s copy] }];
        gPBChangeCount++;
    }
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) {
        orig_pbSetString(self, _cmd, s);
        @synchronized (gPBLock) { gPBChangeCount++; }
    }
#endif
}

static NSArray<NSString *> *(*orig_pbStrings)(id, SEL);
static NSArray<NSString *> *my_pbStrings(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbStrings(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
    return @[];
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) return orig_pbStrings(self, _cmd);
    return nil;
#else
    @synchronized (gPBLock) {
        NSMutableArray *out = [NSMutableArray array];
        for (NSDictionary *item in gPBItems) {
            id v = item[@"public.utf8-plain-text"] ?: item[@"public.text"];
            if ([v isKindOfClass:[NSString class]]) [out addObject:v];
        }
        return out.count ? out : nil;
    }
#endif
}

static void (*orig_pbSetStrings)(id, SEL, NSArray<NSString *> *);
static void my_pbSetStrings(id self, SEL _cmd, NSArray<NSString *> *arr) {
    if (!isGeneralPB(self)) { orig_pbSetStrings(self, _cmd, arr); return; }
#if LC_PASTEBOARD_MODE == 1
    @synchronized (gPBLock) {
        [gPBItems removeAllObjects];
        for (NSString *s in arr) {
            if ([s isKindOfClass:[NSString class]]) {
                [gPBItems addObject:@{ @"public.utf8-plain-text": [s copy] }];
            }
        }
        gPBChangeCount++;
    }
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) {
        orig_pbSetStrings(self, _cmd, arr);
        @synchronized (gPBLock) { gPBChangeCount++; }
    }
#endif
}

static BOOL (*orig_pbHasStrings)(id, SEL);
static BOOL my_pbHasStrings(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbHasStrings(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
    return NO;
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) return orig_pbHasStrings(self, _cmd);
    return NO;
#else
    return my_pbString(self, _cmd).length > 0;
#endif
}

static NSURL *(*orig_pbURL)(id, SEL);
static NSURL *my_pbURL(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbURL(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
    return nil;
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) return orig_pbURL(self, _cmd);
    return nil;
#else
    @synchronized (gPBLock) {
        for (NSDictionary *item in gPBItems) {
            id v = item[@"public.url"];
            if ([v isKindOfClass:[NSURL class]]) return v;
            if ([v isKindOfClass:[NSString class]]) return [NSURL URLWithString:v];
        }
        return nil;
    }
#endif
}

static void (*orig_pbSetURL)(id, SEL, NSURL *);
static void my_pbSetURL(id self, SEL _cmd, NSURL *u) {
    if (!isGeneralPB(self)) { orig_pbSetURL(self, _cmd, u); return; }
#if LC_PASTEBOARD_MODE == 1
    @synchronized (gPBLock) {
        [gPBItems removeAllObjects];
        if (u) [gPBItems addObject:@{ @"public.url": u, @"public.utf8-plain-text": u.absoluteString ?: @"" }];
        gPBChangeCount++;
    }
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) {
        orig_pbSetURL(self, _cmd, u);
        @synchronized (gPBLock) { gPBChangeCount++; }
    }
#endif
}

static NSArray<NSURL *> *(*orig_pbURLs)(id, SEL);
static NSArray<NSURL *> *my_pbURLs(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbURLs(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
    return nil;
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) return orig_pbURLs(self, _cmd);
    return nil;
#else
    @synchronized (gPBLock) {
        NSMutableArray<NSURL *> *out = [NSMutableArray array];
        for (NSDictionary *item in gPBItems) {
            id v = item[@"public.url"];
            if ([v isKindOfClass:[NSURL class]]) [out addObject:v];
            else if ([v isKindOfClass:[NSString class]]) {
                NSURL *u = [NSURL URLWithString:v];
                if (u) [out addObject:u];
            }
        }
        return out.count ? out : nil;
    }
#endif
}

static void (*orig_pbSetURLs)(id, SEL, NSArray<NSURL *> *);
static void my_pbSetURLs(id self, SEL _cmd, NSArray<NSURL *> *urls) {
    if (!isGeneralPB(self)) { orig_pbSetURLs(self, _cmd, urls); return; }
#if LC_PASTEBOARD_MODE == 1
    @synchronized (gPBLock) {
        [gPBItems removeAllObjects];
        for (NSURL *u in urls) {
            if ([u isKindOfClass:[NSURL class]]) {
                [gPBItems addObject:@{ @"public.url": u, @"public.utf8-plain-text": u.absoluteString ?: @"" }];
            }
        }
        gPBChangeCount++;
    }
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) {
        orig_pbSetURLs(self, _cmd, urls);
        @synchronized (gPBLock) { gPBChangeCount++; }
    }
#endif
}

static BOOL (*orig_pbHasURLs)(id, SEL);
static BOOL my_pbHasURLs(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbHasURLs(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
    return NO;
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) return orig_pbHasURLs(self, _cmd);
    return NO;
#else
    return my_pbURL(self, _cmd) != nil;
#endif
}

static UIImage *(*orig_pbImage)(id, SEL);
static UIImage *my_pbImage(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbImage(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
    return nil;
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) return orig_pbImage(self, _cmd);
    return nil;
#else
    @synchronized (gPBLock) {
        for (NSDictionary *item in gPBItems) {
            id v = item[@"public.png"] ?: item[@"public.jpeg"] ?: item[@"public.image"];
            if ([v isKindOfClass:[UIImage class]]) return v;
            if ([v isKindOfClass:[NSData class]]) return [UIImage imageWithData:v];
        }
        return nil;
    }
#endif
}

static void (*orig_pbSetImage)(id, SEL, UIImage *);
static void my_pbSetImage(id self, SEL _cmd, UIImage *img) {
    if (!isGeneralPB(self)) { orig_pbSetImage(self, _cmd, img); return; }
#if LC_PASTEBOARD_MODE == 1
    @synchronized (gPBLock) {
        [gPBItems removeAllObjects];
        if (img) [gPBItems addObject:@{ @"public.image": img }];
        gPBChangeCount++;
    }
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) {
        orig_pbSetImage(self, _cmd, img);
        @synchronized (gPBLock) { gPBChangeCount++; }
    }
#endif
}

static NSArray<UIImage *> *(*orig_pbImages)(id, SEL);
static NSArray<UIImage *> *my_pbImages(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbImages(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
    return nil;
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) return orig_pbImages(self, _cmd);
    return nil;
#else
    @synchronized (gPBLock) {
        NSMutableArray<UIImage *> *out = [NSMutableArray array];
        for (NSDictionary *item in gPBItems) {
            id v = item[@"public.png"] ?: item[@"public.jpeg"] ?: item[@"public.image"];
            if ([v isKindOfClass:[UIImage class]]) [out addObject:v];
            else if ([v isKindOfClass:[NSData class]]) {
                UIImage *im = [UIImage imageWithData:v];
                if (im) [out addObject:im];
            }
        }
        return out.count ? out : nil;
    }
#endif
}

static void (*orig_pbSetImages)(id, SEL, NSArray<UIImage *> *);
static void my_pbSetImages(id self, SEL _cmd, NSArray<UIImage *> *imgs) {
    if (!isGeneralPB(self)) { orig_pbSetImages(self, _cmd, imgs); return; }
#if LC_PASTEBOARD_MODE == 1
    @synchronized (gPBLock) {
        [gPBItems removeAllObjects];
        for (UIImage *im in imgs) {
            if ([im isKindOfClass:[UIImage class]]) [gPBItems addObject:@{ @"public.image": im }];
        }
        gPBChangeCount++;
    }
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) {
        orig_pbSetImages(self, _cmd, imgs);
        @synchronized (gPBLock) { gPBChangeCount++; }
    }
#endif
}

static BOOL (*orig_pbHasImages)(id, SEL);
static BOOL my_pbHasImages(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbHasImages(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
    return NO;
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) return orig_pbHasImages(self, _cmd);
    return NO;
#else
    return my_pbImage(self, _cmd) != nil;
#endif
}

static NSArray<NSDictionary<NSString *, id> *> *(*orig_pbItems)(id, SEL);
static NSArray<NSDictionary<NSString *, id> *> *my_pbItems(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbItems(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
    return @[];
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) return orig_pbItems(self, _cmd);
    return @[];
#else
    @synchronized (gPBLock) { return [gPBItems copy]; }
#endif
}

static void (*orig_pbSetItems)(id, SEL, NSArray<NSDictionary<NSString *, id> *> *);
static void my_pbSetItems(id self, SEL _cmd, NSArray<NSDictionary<NSString *, id> *> *items) {
    if (!isGeneralPB(self)) { orig_pbSetItems(self, _cmd, items); return; }
#if LC_PASTEBOARD_MODE == 1
    @synchronized (gPBLock) {
        [gPBItems removeAllObjects];
        if ([items isKindOfClass:[NSArray class]]) [gPBItems addObjectsFromArray:items];
        gPBChangeCount++;
    }
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) {
        orig_pbSetItems(self, _cmd, items);
        @synchronized (gPBLock) { gPBChangeCount++; }
    }
#endif
}

static void (*orig_pbSetItemsOpts)(id, SEL, NSArray<NSDictionary<NSString *, id> *> *, NSDictionary *);
static void my_pbSetItemsOpts(id self, SEL _cmd, NSArray<NSDictionary<NSString *, id> *> *items, NSDictionary *opts) {
    // social_media_share memakai setItems:options: untuk kirim sticker ke Instagram/FB -> selalu izinkan.
    BOOL isSocialShare = NO;
    if ([items isKindOfClass:[NSArray class]]) {
        for (id d in items) {
            if (![d isKindOfClass:[NSDictionary class]]) continue;
            for (id k in (NSDictionary *)d) {
                if ([k isKindOfClass:[NSString class]] &&
                    ([(NSString *)k hasPrefix:@"com.instagram."] || [(NSString *)k hasPrefix:@"com.facebook."])) {
                    isSocialShare = YES; break;
                }
            }
            if (isSocialShare) break;
        }
    }
    if (!isGeneralPB(self) || isSocialShare) {
        orig_pbSetItemsOpts(self, _cmd, items, opts);
        return;
    }
#if LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) {
        orig_pbSetItemsOpts(self, _cmd, items, opts);
        @synchronized (gPBLock) { gPBChangeCount++; }
    }
#else
    my_pbSetItems(self, _cmd, items);
#endif
}

static void (*orig_pbAddItems)(id, SEL, NSArray<NSDictionary<NSString *, id> *> *);
static void my_pbAddItems(id self, SEL _cmd, NSArray<NSDictionary<NSString *, id> *> *items) {
    if (!isGeneralPB(self)) { orig_pbAddItems(self, _cmd, items); return; }
#if LC_PASTEBOARD_MODE == 1
    @synchronized (gPBLock) {
        if ([items isKindOfClass:[NSArray class]]) [gPBItems addObjectsFromArray:items];
        gPBChangeCount++;
    }
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) {
        orig_pbAddItems(self, _cmd, items);
        @synchronized (gPBLock) { gPBChangeCount++; }
    }
#endif
}

static NSArray<NSString *> *(*orig_pbTypes)(id, SEL);
static NSArray<NSString *> *my_pbTypes(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbTypes(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
    return @[];
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) return orig_pbTypes(self, _cmd);
    return @[];
#else
    @synchronized (gPBLock) {
        NSMutableSet *s = [NSMutableSet set];
        for (NSDictionary *d in gPBItems) [s addObjectsFromArray:d.allKeys];
        return s.allObjects;
    }
#endif
}

static id (*orig_pbValueForType)(id, SEL, NSString *);
static id my_pbValueForType(id self, SEL _cmd, NSString *type) {
    if (!isGeneralPB(self)) return orig_pbValueForType(self, _cmd, type);
#if LC_PASTEBOARD_MODE == 2
    return nil;
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) return orig_pbValueForType(self, _cmd, type);
    return nil;
#else
    @synchronized (gPBLock) {
        for (NSDictionary *d in gPBItems) { if (d[type]) return d[type]; }
        return nil;
    }
#endif
}

static NSData *(*orig_pbDataForType)(id, SEL, NSString *);
static NSData *my_pbDataForType(id self, SEL _cmd, NSString *type) {
    if (!isGeneralPB(self)) return orig_pbDataForType(self, _cmd, type);
#if LC_PASTEBOARD_MODE == 2
    return nil;
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) return orig_pbDataForType(self, _cmd, type);
    return nil;
#else
    id v = my_pbValueForType(self, _cmd, type);
    if ([v isKindOfClass:[NSData class]]) return v;
    if ([v isKindOfClass:[NSString class]]) return [v dataUsingEncoding:NSUTF8StringEncoding];
    return nil;
#endif
}

static void (*orig_pbSetValueForType)(id, SEL, id, NSString *);
static void my_pbSetValueForType(id self, SEL _cmd, id value, NSString *type) {
    if (!isGeneralPB(self)) { orig_pbSetValueForType(self, _cmd, value, type); return; }
#if LC_PASTEBOARD_MODE == 1
    @synchronized (gPBLock) {
        [gPBItems removeAllObjects];
        if (value && type) [gPBItems addObject:@{ type: value }];
        gPBChangeCount++;
    }
#elif LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) {
        orig_pbSetValueForType(self, _cmd, value, type);
        @synchronized (gPBLock) { gPBChangeCount++; }
    }
#endif
}

static void (*orig_pbSetDataForType)(id, SEL, NSData *, NSString *);
static void my_pbSetDataForType(id self, SEL _cmd, NSData *data, NSString *type) {
    if (!isGeneralPB(self)) { orig_pbSetDataForType(self, _cmd, data, type); return; }
#if LC_PASTEBOARD_MODE == 3
    if (allowInteractiveGeneralPB()) {
        orig_pbSetDataForType(self, _cmd, data, type);
        @synchronized (gPBLock) { gPBChangeCount++; }
    }
#else
    my_pbSetValueForType(self, _cmd, data, type);
#endif
}

// changeCount SELALU diisolasi di semua mode (1/2/3) untuk mencegah fingerprinting & polling lintas container!
static NSInteger (*orig_pbChangeCount)(id, SEL);
static NSInteger my_pbChangeCount(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbChangeCount(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
    return 0;
#else
    @synchronized (gPBLock) { return gPBChangeCount; }
#endif
}

static void installPasteboardHooksOnClass(Class pbCls) {
    if (!pbCls) return;
    hookInstanceMethod(pbCls, @selector(string), (IMP)my_pbString, (IMP *)&orig_pbString);
    hookInstanceMethod(pbCls, @selector(setString:), (IMP)my_pbSetString, (IMP *)&orig_pbSetString);
    hookInstanceMethod(pbCls, @selector(strings), (IMP)my_pbStrings, (IMP *)&orig_pbStrings);
    hookInstanceMethod(pbCls, @selector(setStrings:), (IMP)my_pbSetStrings, (IMP *)&orig_pbSetStrings);
    hookInstanceMethod(pbCls, @selector(hasStrings), (IMP)my_pbHasStrings, (IMP *)&orig_pbHasStrings);
    hookInstanceMethod(pbCls, @selector(URL), (IMP)my_pbURL, (IMP *)&orig_pbURL);
    hookInstanceMethod(pbCls, @selector(setURL:), (IMP)my_pbSetURL, (IMP *)&orig_pbSetURL);
    hookInstanceMethod(pbCls, @selector(URLs), (IMP)my_pbURLs, (IMP *)&orig_pbURLs);
    hookInstanceMethod(pbCls, @selector(setURLs:), (IMP)my_pbSetURLs, (IMP *)&orig_pbSetURLs);
    hookInstanceMethod(pbCls, @selector(hasURLs), (IMP)my_pbHasURLs, (IMP *)&orig_pbHasURLs);
    hookInstanceMethod(pbCls, @selector(image), (IMP)my_pbImage, (IMP *)&orig_pbImage);
    hookInstanceMethod(pbCls, @selector(setImage:), (IMP)my_pbSetImage, (IMP *)&orig_pbSetImage);
    hookInstanceMethod(pbCls, @selector(images), (IMP)my_pbImages, (IMP *)&orig_pbImages);
    hookInstanceMethod(pbCls, @selector(setImages:), (IMP)my_pbSetImages, (IMP *)&orig_pbSetImages);
    hookInstanceMethod(pbCls, @selector(hasImages), (IMP)my_pbHasImages, (IMP *)&orig_pbHasImages);
    hookInstanceMethod(pbCls, @selector(items), (IMP)my_pbItems, (IMP *)&orig_pbItems);
    hookInstanceMethod(pbCls, @selector(setItems:), (IMP)my_pbSetItems, (IMP *)&orig_pbSetItems);
    hookInstanceMethod(pbCls, @selector(setItems:options:), (IMP)my_pbSetItemsOpts, (IMP *)&orig_pbSetItemsOpts);
    hookInstanceMethod(pbCls, @selector(addItems:), (IMP)my_pbAddItems, (IMP *)&orig_pbAddItems);
    hookInstanceMethod(pbCls, @selector(pasteboardTypes), (IMP)my_pbTypes, (IMP *)&orig_pbTypes);
    hookInstanceMethod(pbCls, @selector(valueForPasteboardType:), (IMP)my_pbValueForType, (IMP *)&orig_pbValueForType);
    hookInstanceMethod(pbCls, @selector(dataForPasteboardType:), (IMP)my_pbDataForType, (IMP *)&orig_pbDataForType);
    hookInstanceMethod(pbCls, @selector(setValue:forPasteboardType:), (IMP)my_pbSetValueForType, (IMP *)&orig_pbSetValueForType);
    hookInstanceMethod(pbCls, @selector(setData:forPasteboardType:), (IMP)my_pbSetDataForType, (IMP *)&orig_pbSetDataForType);
    hookInstanceMethod(pbCls, @selector(changeCount), (IMP)my_pbChangeCount, (IMP *)&orig_pbChangeCount);
}
#endif

#pragma mark - 7. UNUserNotificationCenter & System UI (shortcutItems + Badge Count) Isolation

#if LC_ISOLATE_NOTIFICATIONS
static NSString *scopeNotifID(NSString *nid) {
    if (![nid isKindOfClass:[NSString class]] || !nid.length) return nid;
    NSString *p = containerPrefix();
    if ([nid hasPrefix:p]) return nid;
    return [p stringByAppendingString:nid];
}

static NSString *safeNotifReqID(id req) {
    if (!req) return nil;
    SEL idSel = NSSelectorFromString(@"identifier");
    if (![req respondsToSelector:idSel]) return nil;
    id val = ((id (*)(id, SEL))objc_msgSend)(req, idSel);
    return [val isKindOfClass:[NSString class]] ? val : nil;
}

static void (*orig_unAddReq)(id, SEL, id, void (^)(NSError *));
static void my_unAddReq(id self, SEL _cmd, id req, void (^handler)(NSError *)) {
    id finalReq = req;
    NSString *ident = safeNotifReqID(req);
    if (ident.length) {
        NSString *scoped = scopeNotifID(ident);
        Class reqCls = NSClassFromString(@"UNNotificationRequest");
        SEL mkSel = NSSelectorFromString(@"requestWithIdentifier:content:trigger:");
        SEL cSel = NSSelectorFromString(@"content");
        SEL tSel = NSSelectorFromString(@"trigger");
        if (reqCls && scoped && ![scoped isEqualToString:ident] &&
            [reqCls respondsToSelector:mkSel] && [req respondsToSelector:cSel] && [req respondsToSelector:tSel]) {
            id content = ((id (*)(id, SEL))objc_msgSend)(req, cSel);
            id trigger = ((id (*)(id, SEL))objc_msgSend)(req, tSel);
            id rebuilt = ((id (*)(Class, SEL, NSString *, id, id))objc_msgSend)(reqCls, mkSel, scoped, content, trigger);
            if (rebuilt) finalReq = rebuilt;
        }
    }
    orig_unAddReq(self, _cmd, finalReq, handler);
}

static void (*orig_unGetPending)(id, SEL, void (^)(NSArray *));
static void my_unGetPending(id self, SEL _cmd, void (^handler)(NSArray *)) {
    if (!handler) { orig_unGetPending(self, _cmd, handler); return; }
    NSString *p = containerPrefix();
    orig_unGetPending(self, _cmd, ^(NSArray *reqs) {
        NSMutableArray *out = [NSMutableArray array];
        Class reqCls = NSClassFromString(@"UNNotificationRequest");
        SEL mkSel = NSSelectorFromString(@"requestWithIdentifier:content:trigger:");
        SEL cSel = NSSelectorFromString(@"content");
        SEL tSel = NSSelectorFromString(@"trigger");
        for (id r in reqs) {
            NSString *ident = safeNotifReqID(r);
            if (![ident hasPrefix:p]) continue;
            NSString *origID = [ident substringFromIndex:p.length];
            if (reqCls && [reqCls respondsToSelector:mkSel] && [r respondsToSelector:cSel] && [r respondsToSelector:tSel]) {
                id content = ((id (*)(id, SEL))objc_msgSend)(r, cSel);
                id trigger = ((id (*)(id, SEL))objc_msgSend)(r, tSel);
                id rebuilt = ((id (*)(Class, SEL, NSString *, id, id))objc_msgSend)(reqCls, mkSel, origID, content, trigger);
                if (rebuilt) { [out addObject:rebuilt]; continue; }
            }
            [out addObject:r];
        }
        handler(out);
    });
}

static void (*orig_unGetDelivered)(id, SEL, void (^)(NSArray *));
static void my_unGetDelivered(id self, SEL _cmd, void (^handler)(NSArray *)) {
    if (!handler) { orig_unGetDelivered(self, _cmd, handler); return; }
    NSString *p = containerPrefix();
    SEL reqSel = NSSelectorFromString(@"request");
    orig_unGetDelivered(self, _cmd, ^(NSArray *notifs) {
        NSMutableArray *out = [NSMutableArray array];
        for (id n in notifs) {
            if (![n respondsToSelector:reqSel]) continue;
            id req = ((id (*)(id, SEL))objc_msgSend)(n, reqSel);
            NSString *ident = safeNotifReqID(req);
            if ([ident hasPrefix:p]) [out addObject:n];
        }
        handler(out);
    });
}

static void (*orig_unRemovePendingIDs)(id, SEL, NSArray<NSString *> *);
static void my_unRemovePendingIDs(id self, SEL _cmd, NSArray<NSString *> *ids) {
    NSMutableArray *mapped = [NSMutableArray arrayWithCapacity:ids.count];
    for (NSString *i in ids) [mapped addObject:scopeNotifID(i)];
    orig_unRemovePendingIDs(self, _cmd, mapped);
}

static void (*orig_unRemoveDeliveredIDs)(id, SEL, NSArray<NSString *> *);
static void my_unRemoveDeliveredIDs(id self, SEL _cmd, NSArray<NSString *> *ids) {
    NSMutableArray *mapped = [NSMutableArray arrayWithCapacity:ids.count];
    for (NSString *i in ids) [mapped addObject:scopeNotifID(i)];
    orig_unRemoveDeliveredIDs(self, _cmd, mapped);
}

static void (*orig_unRemoveAllPending)(id, SEL);
static void my_unRemoveAllPending(id self, SEL _cmd) {
    if (!orig_unGetPending || !orig_unRemovePendingIDs) {
        orig_unRemoveAllPending(self, _cmd);
        return;
    }
    NSString *p = containerPrefix();
    orig_unGetPending(self, NSSelectorFromString(@"getPendingNotificationRequestsWithCompletionHandler:"), ^(NSArray *reqs) {
        NSMutableArray *mine = [NSMutableArray array];
        for (id r in reqs) {
            NSString *ident = safeNotifReqID(r);
            if ([ident hasPrefix:p]) [mine addObject:ident];
        }
        if (mine.count) {
            orig_unRemovePendingIDs(self, NSSelectorFromString(@"removePendingNotificationRequestsWithIdentifiers:"), mine);
        }
    });
}

static void (*orig_unRemoveAllDelivered)(id, SEL);
static void my_unRemoveAllDelivered(id self, SEL _cmd) {
    if (!orig_unGetDelivered || !orig_unRemoveDeliveredIDs) {
        orig_unRemoveAllDelivered(self, _cmd);
        return;
    }
    NSString *p = containerPrefix();
    SEL reqSel = NSSelectorFromString(@"request");
    orig_unGetDelivered(self, NSSelectorFromString(@"getDeliveredNotificationsWithCompletionHandler:"), ^(NSArray *notifs) {
        NSMutableArray *mine = [NSMutableArray array];
        for (id n in notifs) {
            if (![n respondsToSelector:reqSel]) continue;
            NSString *ident = safeNotifReqID(((id (*)(id, SEL))objc_msgSend)(n, reqSel));
            if ([ident hasPrefix:p]) [mine addObject:ident];
        }
        if (mine.count) {
            orig_unRemoveDeliveredIDs(self, NSSelectorFromString(@"removeDeliveredNotificationsWithIdentifiers:"), mine);
        }
    });
}
#endif

#if LC_ISOLATE_SYSTEM_UI
static NSObject *gSysUILock;
static NSArray<UIApplicationShortcutItem *> *gIsoShortcutItems;
static NSInteger gIsoBadgeCount = 0;

static void (*orig_setShortcutItems)(id, SEL, NSArray<UIApplicationShortcutItem *> *);
static void my_setShortcutItems(id self, SEL _cmd, NSArray<UIApplicationShortcutItem *> *items) {
    (void)self; (void)_cmd;
    @synchronized (gSysUILock) {
        gIsoShortcutItems = [items copy];
    }
}

static NSArray<UIApplicationShortcutItem *> *(*orig_shortcutItems)(id, SEL);
static NSArray<UIApplicationShortcutItem *> *my_shortcutItems(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    @synchronized (gSysUILock) {
        return gIsoShortcutItems ?: @[];
    }
}

static void (*orig_setAppBadge)(id, SEL, NSInteger);
static void my_setAppBadge(id self, SEL _cmd, NSInteger count) {
    (void)self; (void)_cmd;
    @synchronized (gSysUILock) {
        gIsoBadgeCount = count;
    }
}

static NSInteger (*orig_appBadge)(id, SEL);
static NSInteger my_appBadge(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    @synchronized (gSysUILock) {
        return gIsoBadgeCount;
    }
}

static void (*orig_unSetBadgeCount)(id, SEL, NSInteger, void (^)(NSError *));
static void my_unSetBadgeCount(id self, SEL _cmd, NSInteger count, void (^completion)(NSError *)) {
    (void)self; (void)_cmd;
    @synchronized (gSysUILock) {
        gIsoBadgeCount = count;
    }
    if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{ completion(nil); });
    }
}
#endif

#if LC_ISOLATE_NOTIFICATIONS || LC_ISOLATE_SYSTEM_UI
static void installNotificationHooksIfLoaded(void) {
    Class un = NSClassFromString(@"UNUserNotificationCenter");
    if (!un) return;
#if LC_ISOLATE_NOTIFICATIONS
    hookInstanceMethod(un, NSSelectorFromString(@"addNotificationRequest:withCompletionHandler:"),
                       (IMP)my_unAddReq, (IMP *)&orig_unAddReq);
    hookInstanceMethod(un, NSSelectorFromString(@"getPendingNotificationRequestsWithCompletionHandler:"),
                       (IMP)my_unGetPending, (IMP *)&orig_unGetPending);
    hookInstanceMethod(un, NSSelectorFromString(@"getDeliveredNotificationsWithCompletionHandler:"),
                       (IMP)my_unGetDelivered, (IMP *)&orig_unGetDelivered);
    hookInstanceMethod(un, NSSelectorFromString(@"removePendingNotificationRequestsWithIdentifiers:"),
                       (IMP)my_unRemovePendingIDs, (IMP *)&orig_unRemovePendingIDs);
    hookInstanceMethod(un, NSSelectorFromString(@"removeDeliveredNotificationsWithIdentifiers:"),
                       (IMP)my_unRemoveDeliveredIDs, (IMP *)&orig_unRemoveDeliveredIDs);
    hookInstanceMethod(un, NSSelectorFromString(@"removeAllPendingNotificationRequests"),
                       (IMP)my_unRemoveAllPending, (IMP *)&orig_unRemoveAllPending);
    hookInstanceMethod(un, NSSelectorFromString(@"removeAllDeliveredNotifications"),
                       (IMP)my_unRemoveAllDelivered, (IMP *)&orig_unRemoveAllDelivered);
#endif
#if LC_ISOLATE_SYSTEM_UI
    if (class_getInstanceMethod(un, NSSelectorFromString(@"setBadgeCount:withCompletionHandler:"))) {
        hookInstanceMethod(un, NSSelectorFromString(@"setBadgeCount:withCompletionHandler:"),
                           (IMP)my_unSetBadgeCount, (IMP *)&orig_unSetBadgeCount);
    }
#endif
}
#endif

#pragma mark - 8. Hardened Keychain Isolation (Passwords + 2-Phase kSecClassKey + Cert/Identity + SecKeyGeneratePair)

#if LC_ENABLE_KEYCHAIN
static NSObject *gLock;
static NSMutableDictionary *gKC;
static NSString *gKCCID;

static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef);
static SecKeyRef (*orig_SecKeyCreateRandomKey)(CFDictionaryRef, CFErrorRef *);
static OSStatus (*orig_SecKeyGeneratePair)(CFDictionaryRef, SecKeyRef *, SecKeyRef *);
static CFDictionaryRef (*orig_SecKeyCopyAttributes)(SecKeyRef);

static NSData *tagPrefixData(void) {
    return [containerPrefix() dataUsingEncoding:NSUTF8StringEncoding];
}

static BOOL dataHasPrefix(NSData *d, NSData *p) {
    return [d isKindOfClass:[NSData class]] && d.length >= p.length &&
           [[d subdataWithRange:NSMakeRange(0, p.length)] isEqualToData:p];
}

static NSData *scopedTag(id tag) {
    NSData *p = tagPrefixData();
    NSData *raw = nil;
    if ([tag isKindOfClass:[NSData class]]) raw = tag;
    else if ([tag isKindOfClass:[NSString class]]) raw = [tag dataUsingEncoding:NSUTF8StringEncoding];
    if (raw && dataHasPrefix(raw, p)) return raw;   // cegah double-prefix
    NSMutableData *m = [p mutableCopy];
    if (raw) [m appendData:raw];
    return m;
}

static NSData *unscopedTag(NSData *t) {
    NSData *p = tagPrefixData();
    if (dataHasPrefix(t, p)) return [t subdataWithRange:NSMakeRange(p.length, t.length - p.length)];
    return t;
}

static NSString *scopedLabel(id lbl) {
    if (![lbl isKindOfClass:[NSString class]]) return lbl;
    NSString *p = containerPrefix();
    if ([lbl hasPrefix:p]) return lbl;
    return [p stringByAppendingString:lbl];
}

static NSString *unscopedLabel(NSString *lbl) {
    if (![lbl isKindOfClass:[NSString class]]) return lbl;
    NSString *p = containerPrefix();
    if ([lbl hasPrefix:p]) return [lbl substringFromIndex:p.length];
    return lbl;
}

static BOOL isKeyClass(NSDictionary *d) {
    return [d[(__bridge id)kSecClass] isEqual:(__bridge id)kSecClassKey];
}

static BOOL isCertOrIdentityClass(NSDictionary *d) {
    id c = d[(__bridge id)kSecClass];
    return [c isEqual:(__bridge id)kSecClassCertificate] ||
           [c isEqual:(__bridge id)kSecClassIdentity];
}

static BOOL isPasswordClass(NSDictionary *d) {
    id c = d[(__bridge id)kSecClass];
    return [c isEqual:(__bridge id)kSecClassGenericPassword] ||
           [c isEqual:(__bridge id)kSecClassInternetPassword];
}

// CRITICAL FIX (-34018 errSecMissingEntitlement):
// Pada build resign LiveContainer, entitlement GF3689X945.gojekSharedKeychain* tidak dimiliki host.
// Membuang kSecAttrAccessGroup asing (kecuali com.apple.token untuk Secure Enclave) mencegah -34018!
static void stripForeignAccessGroup(NSMutableDictionary *m) {
    id grp = m[(__bridge id)kSecAttrAccessGroup];
    if (![grp isKindOfClass:[NSString class]]) return;
    if ([grp isEqualToString:(__bridge NSString *)kSecAttrAccessGroupToken]) return;
    [m removeObjectForKey:(__bridge id)kSecAttrAccessGroup];
}

static BOOL isExplicitlyNonPermanent(NSDictionary *d) {
    id perm = d[(__bridge id)kSecAttrIsPermanent];
    return ([perm isKindOfClass:[NSNumber class]] && ![perm boolValue]);
}

static NSDictionary *scopeKeyDict(NSDictionary *d, BOOL forceTag) {
    if (!d) return nil;
    NSMutableDictionary *m = [d mutableCopy];
    stripForeignAccessGroup(m);
    id tag = m[(__bridge id)kSecAttrApplicationTag];
    if (tag) {
        m[(__bridge id)kSecAttrApplicationTag] = scopedTag(tag);
    } else if (forceTag && !isExplicitlyNonPermanent(m)) {
        m[(__bridge id)kSecAttrApplicationTag] = tagPrefixData();
    }
    if ([m[(__bridge id)kSecAttrLabel] isKindOfClass:[NSString class]]) {
        m[(__bridge id)kSecAttrLabel] = scopedLabel(m[(__bridge id)kSecAttrLabel]);
    }
    return m;
}

static BOOL isExplicitlyPermanent(NSDictionary *d) {
    id perm = d[(__bridge id)kSecAttrIsPermanent];
    return ([perm isKindOfClass:[NSNumber class]] && [perm boolValue]);
}

// FIX v11 (K4): hormati kSecAttrIsPermanent = @NO (kunci ephemeral in-memory tidak perlu dipaksa tag).
// Ghidra (GotoUtils CryptoRSAManager.generateRSAKeyPair @0x8c38): SecKeyGeneratePair dipanggil hanya dengan
// kSecAttrKeyType + kSecAttrKeySizeInBits (tanpa kSecAttrIsPermanent -> default Apple = TIDAK disimpan).
// Karena itu tag paksa hanya dipasang jika ada kSecAttrIsPermanent = @YES (top-level atau sub-dict).
static NSDictionary *scopeKeyParams(NSDictionary *p, BOOL forceTag) {
    if (!p) return nil;
    BOOL anyPermanent = isExplicitlyPermanent(p);
    for (id sub in @[(__bridge id)kSecPrivateKeyAttrs, (__bridge id)kSecPublicKeyAttrs]) {
        NSDictionary *sd = p[sub];
        if ([sd isKindOfClass:[NSDictionary class]] && isExplicitlyPermanent(sd)) anyPermanent = YES;
    }
    forceTag = forceTag && anyPermanent;
    BOOL topNonPerm = isExplicitlyNonPermanent(p);
    BOOL hasSubDict = NO;
    for (id sub in @[(__bridge id)kSecPrivateKeyAttrs, (__bridge id)kSecPublicKeyAttrs]) {
        if ([p[sub] isKindOfClass:[NSDictionary class]]) hasSubDict = YES;
    }
    NSMutableDictionary *m = [scopeKeyDict(p, forceTag && !hasSubDict && !topNonPerm) mutableCopy];
    for (id sub in @[(__bridge id)kSecPrivateKeyAttrs, (__bridge id)kSecPublicKeyAttrs]) {
        NSDictionary *sd = m[sub];
        if ([sd isKindOfClass:[NSDictionary class]]) {
            BOOL subForce = forceTag && !topNonPerm && !isExplicitlyNonPermanent(sd);
            m[sub] = scopeKeyDict(sd, subForce);
        }
    }
    return m;
}

static NSDictionary *scopeCertDict(NSDictionary *d, BOOL forceLabel) {
    if (!d) return nil;
    NSMutableDictionary *m = [d mutableCopy];
    stripForeignAccessGroup(m);
    id lbl = m[(__bridge id)kSecAttrLabel];
    if ([lbl isKindOfClass:[NSString class]]) {
        m[(__bridge id)kSecAttrLabel] = scopedLabel(lbl);
    } else if (forceLabel) {
        m[(__bridge id)kSecAttrLabel] = containerPrefix();
    }
    return m;
}

static id unscopeObj(id o) {
    if ([o isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *m = nil;
        NSData *t = o[(__bridge id)kSecAttrApplicationTag];
        if ([t isKindOfClass:[NSData class]]) {
            NSData *u = unscopedTag(t);
            if (u != t) { m = [o mutableCopy]; m[(__bridge id)kSecAttrApplicationTag] = u; }
        }
        NSString *lbl = o[(__bridge id)kSecAttrLabel];
        if ([lbl isKindOfClass:[NSString class]]) {
            NSString *ul = unscopedLabel(lbl);
            if (ul != lbl) { if (!m) m = [o mutableCopy]; m[(__bridge id)kSecAttrLabel] = ul; }
        }
        return m ?: o;
    }
    if ([o isKindOfClass:[NSArray class]]) {
        NSMutableArray *a = [NSMutableArray array];
        BOOL changed = NO;
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

static BOOL realItemBelongsToContainer(NSDictionary *item, BOOL byLabel) {
    if (byLabel) {
        NSString *lbl = item[(__bridge id)kSecAttrLabel];
        return [lbl isKindOfClass:[NSString class]] && [lbl hasPrefix:containerPrefix()];
    }
    NSData *tag = item[(__bridge id)kSecAttrApplicationTag];
    if (dataHasPrefix(tag, tagPrefixData())) return YES;
    NSString *lbl = item[(__bridge id)kSecAttrLabel];
    return [lbl isKindOfClass:[NSString class]] && [lbl hasPrefix:containerPrefix()];
}

static id formatRealKeyItem(NSDictionary *it, NSDictionary *origQuery) {
    BOOL wData = [origQuery[(__bridge id)kSecReturnData] boolValue];
    BOOL wAttr = [origQuery[(__bridge id)kSecReturnAttributes] boolValue];
    BOOL wRef  = [origQuery[(__bridge id)kSecReturnRef] boolValue];
    BOOL wPRef = [origQuery[(__bridge id)kSecReturnPersistentRef] boolValue];
    if (!wData && !wAttr && !wRef && !wPRef) return nil;
    NSDictionary *clean = unscopeObj(it);
    if (wAttr) {
        NSMutableDictionary *m = [clean mutableCopy];
        if (!wData) [m removeObjectForKey:(__bridge id)kSecValueData];
        if (!wRef)  [m removeObjectForKey:(__bridge id)kSecValueRef];
        if (!wPRef) [m removeObjectForKey:(__bridge id)kSecValuePersistentRef];
        return m;
    }
    if (wRef)  return clean[(__bridge id)kSecValueRef];
    if (wPRef) return clean[(__bridge id)kSecValuePersistentRef];
    return clean[(__bridge id)kSecValueData];
}

// CRITICAL FIX v11 (K2): 2-Phase filteredRealCopyMatching!
// Fase 1: enumerasi metadata HANYA dengan kSecReturnAttributes + kSecReturnPersistentRef + kSecUseAuthenticationUISkip
//         sehingga TIDAK PERNAH memicu prompt Face ID/Touch ID untuk kunci Secure Enclave milik container lain!
// Fase 2: jika caller meminta kSecReturnRef/kSecReturnData, ambil ulang HANYA untuk persistentRef milik container ini.
static OSStatus filteredRealCopyMatching(NSDictionary *q, CFTypeRef *result, BOOL byLabel) {
    NSMutableDictionary *iq = [byLabel ? scopeCertDict(q, NO) : scopeKeyDict(q, NO) mutableCopy];
    [iq removeObjectForKey:(__bridge id)kSecReturnData];
    [iq removeObjectForKey:(__bridge id)kSecReturnRef];
    [iq removeObjectForKey:(__bridge id)kSecUseAuthenticationContext];
    iq[(__bridge id)kSecReturnAttributes] = @YES;
    iq[(__bridge id)kSecReturnPersistentRef] = @YES;
    iq[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
    iq[(__bridge id)kSecUseAuthenticationUI] = (__bridge id)kSecUseAuthenticationUISkip;

    CFTypeRef raw = NULL;
    OSStatus st = orig_SecItemCopyMatching((__bridge CFDictionaryRef)iq, &raw);
    if (st != errSecSuccess || !raw) {
        if (raw) CFRelease(raw);
        return st;
    }
    id obj = CFBridgingRelease(raw);
    NSArray *list = [obj isKindOfClass:[NSArray class]] ? obj : ([obj isKindOfClass:[NSDictionary class]] ? @[obj] : @[]);
    NSMutableArray<NSDictionary *> *mine = [NSMutableArray array];
    for (id e in list) {
        if ([e isKindOfClass:[NSDictionary class]] && realItemBelongsToContainer(e, byLabel)) {
            [mine addObject:e];
        }
    }
    if (!mine.count) return errSecItemNotFound;

    BOOL needSensitive = [q[(__bridge id)kSecReturnRef] boolValue] || [q[(__bridge id)kSecReturnData] boolValue];
    id lim = q[(__bridge id)kSecMatchLimit];
    BOOL wantMany = [lim isEqual:(__bridge id)kSecMatchLimitAll] ||
                    ([lim isKindOfClass:[NSNumber class]] && [lim integerValue] > 1);
    NSInteger cap = wantMany
        ? ([lim isKindOfClass:[NSNumber class]] ? [lim integerValue] : (NSInteger)mine.count)
        : 1;

    if (!result) return errSecSuccess;

    NSMutableArray *out = [NSMutableArray array];
    for (NSInteger i = 0; i < (NSInteger)mine.count && i < cap; i++) {
        NSDictionary *entry = mine[i];
        if (needSensitive) {
            NSData *pref = entry[(__bridge id)kSecValuePersistentRef];
            if (!pref) continue;
            NSMutableDictionary *fq = [NSMutableDictionary dictionary];
            fq[(__bridge id)kSecValuePersistentRef] = pref;
            if ([q[(__bridge id)kSecReturnData] boolValue])          fq[(__bridge id)kSecReturnData] = @YES;
            if ([q[(__bridge id)kSecReturnRef] boolValue])           fq[(__bridge id)kSecReturnRef] = @YES;
            if ([q[(__bridge id)kSecReturnAttributes] boolValue])    fq[(__bridge id)kSecReturnAttributes] = @YES;
            if ([q[(__bridge id)kSecReturnPersistentRef] boolValue]) fq[(__bridge id)kSecReturnPersistentRef] = @YES;
            if (q[(__bridge id)kSecUseAuthenticationContext])        fq[(__bridge id)kSecUseAuthenticationContext] = q[(__bridge id)kSecUseAuthenticationContext];
            if (q[(__bridge id)kSecUseAuthenticationUI])             fq[(__bridge id)kSecUseAuthenticationUI] = q[(__bridge id)kSecUseAuthenticationUI];
            if (q[(__bridge id)kSecUseDataProtectionKeychain])       fq[(__bridge id)kSecUseDataProtectionKeychain] = q[(__bridge id)kSecUseDataProtectionKeychain];
            CFTypeRef itemRaw = NULL;
            OSStatus ist = orig_SecItemCopyMatching((__bridge CFDictionaryRef)fq, &itemRaw);
            if (ist == errSecSuccess && itemRaw) {
                unscopeResult(&itemRaw);
                id itemObj = CFBridgingRelease(itemRaw);
                if (itemObj) [out addObject:itemObj];
            } else if (itemRaw) {
                CFRelease(itemRaw);
            } else if (!wantMany && ist != errSecItemNotFound) {
                return ist;
            }
        } else {
            id f = formatRealKeyItem(entry, q);
            if (f) [out addObject:f];
        }
    }

    BOOL wantAnyReturn = [q[(__bridge id)kSecReturnData] boolValue] ||
                         [q[(__bridge id)kSecReturnAttributes] boolValue] ||
                         [q[(__bridge id)kSecReturnRef] boolValue] ||
                         [q[(__bridge id)kSecReturnPersistentRef] boolValue];
    if (wantAnyReturn && !out.count) {
        *result = NULL;
        return errSecItemNotFound;
    }

    if (wantMany) {
        *result = out.count ? CFRetain((__bridge CFTypeRef)out) : NULL;
    } else {
        *result = out.count ? CFRetain((__bridge CFTypeRef)out[0]) : NULL;
    }
    return errSecSuccess;
}

static OSStatus filteredRealDelete(NSDictionary *q, BOOL byLabel) {
    NSMutableDictionary *iq = [byLabel ? scopeCertDict(q, NO) : scopeKeyDict(q, NO) mutableCopy];
    [iq removeObjectForKey:(__bridge id)kSecReturnData];
    [iq removeObjectForKey:(__bridge id)kSecReturnRef];
    [iq removeObjectForKey:(__bridge id)kSecUseAuthenticationContext];
    iq[(__bridge id)kSecReturnAttributes] = @YES;
    iq[(__bridge id)kSecReturnPersistentRef] = @YES;
    iq[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
    iq[(__bridge id)kSecUseAuthenticationUI] = (__bridge id)kSecUseAuthenticationUISkip;

    CFTypeRef raw = NULL;
    OSStatus st = orig_SecItemCopyMatching((__bridge CFDictionaryRef)iq, &raw);
    if (st != errSecSuccess || !raw) {
        if (raw) CFRelease(raw);
        return st;
    }
    id obj = CFBridgingRelease(raw);
    NSArray *list = [obj isKindOfClass:[NSArray class]] ? obj : ([obj isKindOfClass:[NSDictionary class]] ? @[obj] : @[]);
    NSUInteger deleted = 0;
    for (id e in list) {
        if (![e isKindOfClass:[NSDictionary class]] || !realItemBelongsToContainer(e, byLabel)) continue;
        NSData *pref = e[(__bridge id)kSecValuePersistentRef];
        if (pref) {
            NSDictionary *delQ = @{ (__bridge id)kSecValuePersistentRef: pref };
            if (orig_SecItemDelete((__bridge CFDictionaryRef)delQ) == errSecSuccess) deleted++;
        }
    }
    return deleted ? errSecSuccess : errSecItemNotFound;
}

static OSStatus filteredRealUpdate(NSDictionary *q, NSDictionary *upd, BOOL byLabel) {
    if (!upd) return errSecParam;
    NSMutableDictionary *iq = [byLabel ? scopeCertDict(q, NO) : scopeKeyDict(q, NO) mutableCopy];
    [iq removeObjectForKey:(__bridge id)kSecReturnData];
    [iq removeObjectForKey:(__bridge id)kSecReturnRef];
    [iq removeObjectForKey:(__bridge id)kSecUseAuthenticationContext];
    iq[(__bridge id)kSecReturnAttributes] = @YES;
    iq[(__bridge id)kSecReturnPersistentRef] = @YES;
    iq[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
    iq[(__bridge id)kSecUseAuthenticationUI] = (__bridge id)kSecUseAuthenticationUISkip;

    CFTypeRef raw = NULL;
    OSStatus st = orig_SecItemCopyMatching((__bridge CFDictionaryRef)iq, &raw);
    if (st != errSecSuccess || !raw) {
        if (raw) CFRelease(raw);
        return st;
    }
    id obj = CFBridgingRelease(raw);
    NSArray *list = [obj isKindOfClass:[NSArray class]] ? obj : ([obj isKindOfClass:[NSDictionary class]] ? @[obj] : @[]);
    NSDictionary *scopedUpd = byLabel ? scopeCertDict(upd, NO) : scopeKeyDict(upd, NO);
    NSUInteger updated = 0;
    OSStatus lastErr = errSecItemNotFound;
    for (id e in list) {
        if (![e isKindOfClass:[NSDictionary class]] || !realItemBelongsToContainer(e, byLabel)) continue;
        NSData *pref = e[(__bridge id)kSecValuePersistentRef];
        if (pref) {
            NSDictionary *updQ = @{ (__bridge id)kSecValuePersistentRef: pref };
            OSStatus ust = orig_SecItemUpdate((__bridge CFDictionaryRef)updQ, (__bridge CFDictionaryRef)scopedUpd);
            if (ust == errSecSuccess) updated++; else lastErr = ust;
        }
    }
    return updated ? errSecSuccess : lastErr;
}

// ---- Access Group Normalization & Deterministic Priority ----
static BOOL isValidTeamID(NSString *s) {
    if (s.length != 10) return NO;
    for (NSUInteger i = 0; i < 10; i++) {
        unichar c = [s characterAtIndex:i];
        BOOL ok = (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
        if (!ok) return NO;
    }
    return YES;
}

static NSString *normGroup(id g) {
    if (![g isKindOfClass:[NSString class]] || ![g length]) return LC_DEFAULT_KC_GROUP;
    NSString *s = g;
    NSRange r = [s rangeOfString:@"."];
    if (r.location == 10 && isValidTeamID([s substringToIndex:10])) {
        return [s substringFromIndex:11];
    }
    return s;
}

static NSInteger groupPriority(NSString *g) {
    if ([g isEqualToString:@"gojekSharedKeychain"]) return 0;
    if ([g isEqualToString:@"gojekSharedKeychainBiometric"]) return 1;
    if ([g isEqualToString:@"gotoSharedKeychain"]) return 2;
    if ([g isEqualToString:@"com.go-jek.gopay"]) return 3;
    return 10;
}

static BOOL itemSync(NSDictionary *d) {
    id s = d[(__bridge id)kSecAttrSynchronizable];
    return [s isKindOfClass:[NSNumber class]] ? [s boolValue] : NO;
}

// CRITICAL FIX v11 (K1): Canonical UTF-8 untuk NSData vs NSString!
// Terbukti di lcisolator.log baris 84-85 AppsFlyer mengirim kSecAttrAccount sebagai NSData UTF-8.
// Menggunakan UTF-8 kanonik menyelaraskan kcKey() dengan attrEquals() (mencegah duplikasi key).
static NSString *strOrEmpty(id v) {
    if (!v) return @"";
    if ([v isKindOfClass:[NSData class]]) {
        NSData *d = (NSData *)v;
        if (!d.length) return @"";
        NSString *utf8 = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if (utf8) return utf8;
        return [@"b64:" stringByAppendingString:[d base64EncodedStringWithOptions:0]];
    }
    return [NSString stringWithFormat:@"%@", v];
}

// Primary key lengkap sesuai Apple Security.framework (Generic & Internet password)
static NSString *kcKey(NSDictionary *a) {
    NSArray *ks = @[
        (__bridge id)kSecClass,
        (__bridge id)kSecAttrService,
        (__bridge id)kSecAttrAccount,
        (__bridge id)kSecAttrSecurityDomain,
        (__bridge id)kSecAttrServer,
        (__bridge id)kSecAttrProtocol,
        (__bridge id)kSecAttrAuthenticationType,
        (__bridge id)kSecAttrPort,
        (__bridge id)kSecAttrPath,
    ];
    NSMutableArray *parts = [NSMutableArray arrayWithCapacity:ks.count + 2];
    for (id k in ks) [parts addObject:strOrEmpty(a[k])];
    [parts addObject:normGroup(a[(__bridge id)kSecAttrAccessGroup])];
    [parts addObject:itemSync(a) ? @"sync" : @"local"];
    return [parts componentsJoinedByString:@"|"];
}

static NSMutableDictionary *kcStore(void) { // panggil di dalam @synchronized(gLock)
    NSString *cid = getContainerID();
    if (!gKC || ![gKCCID isEqualToString:cid]) {
        BOOL prevIO = tInInternalIO;
        tInInternalIO = YES;
        NSDictionary *d = nil;
        NSData *raw = [NSData dataWithContentsOfFile:fakeKeychainPath()];
        if (raw.length) {
            id parsed = [NSPropertyListSerialization propertyListWithData:raw options:0 format:NULL error:nil];
            if ([parsed isKindOfClass:[NSDictionary class]]) d = parsed;
        }
        gKC = [NSMutableDictionary dictionary];
        // Otomatis me-reindex key lama v10 (termasuk key Base64 NSData -> UTF-8 kanonik v11).
        [d enumerateKeysAndObjectsUsingBlock:^(id k, id v, BOOL *stop) {
            (void)k; (void)stop;
            if ([v isKindOfClass:[NSDictionary class]]) {
                NSMutableDictionary *m = [v mutableCopy];
                if (!m[(__bridge id)kSecAttrAccessGroup]) {
                    m[(__bridge id)kSecAttrAccessGroup] = LC_DEFAULT_KC_GROUP;
                }
                gKC[kcKey(m)] = m;
            }
        }];
        gKCCID = [cid copy];
        tInInternalIO = prevIO;
        LCLog(@"keychain loaded (%@), %lu item", cid, (unsigned long)gKC.count);
    }
    return gKC;
}

static void kcSave(void) {
    BOOL prevIO = tInInternalIO;
    tInInternalIO = YES;
    NSError *err = nil;
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:gKC
                                                              format:NSPropertyListBinaryFormat_v1_0
                                                             options:0
                                                               error:&err];
    if (!data || ![data writeToFile:fakeKeychainPath()
                            options:(NSDataWritingAtomic | NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication)
                              error:&err]) {
        LCLog(@"WARN gagal save keychain: %@", err.localizedDescription);
    }
    tInInternalIO = prevIO;
}

static NSMutableDictionary *sanitize(NSDictionary *src) {
    NSSet *drop = [NSSet setWithObjects:
        (__bridge id)kSecReturnData, (__bridge id)kSecReturnAttributes,
        (__bridge id)kSecReturnRef, (__bridge id)kSecReturnPersistentRef,
        (__bridge id)kSecMatchLimit, (__bridge id)kSecUseAuthenticationContext,
        (__bridge id)kSecUseAuthenticationUI, (__bridge id)kSecUseDataProtectionKeychain, nil];
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    [src enumerateKeysAndObjectsUsingBlock:^(id k, id v, BOOL *stop) {
        (void)stop;
        if (![k isKindOfClass:[NSString class]] || [drop containsObject:k]) return;
        if ([v isKindOfClass:[NSString class]] || [v isKindOfClass:[NSData class]] ||
            [v isKindOfClass:[NSNumber class]] || [v isKindOfClass:[NSDate class]]) {
            out[k] = v;
        }
    }];
    if (src[(__bridge id)kSecAttrAccessControl]) {
        out[@"_lc_hasAccessControl"] = @YES;
    }
    return out;
}

// Perbandingan atribut yang konsisten untuk nil vs @"" serta NSString vs NSData UTF-8
static BOOL attrEquals(id iv, id qv) {
    if (!qv) return YES;
    if ([qv isKindOfClass:[NSString class]] && [(NSString *)qv length] == 0) {
        if (!iv) return YES;
        if ([iv isKindOfClass:[NSString class]] && [(NSString *)iv length] == 0) return YES;
        if ([iv isKindOfClass:[NSData class]] && [(NSData *)iv length] == 0) return YES;
        return NO;
    }
    if ([qv isKindOfClass:[NSData class]] && [(NSData *)qv length] == 0) {
        if (!iv) return YES;
        if ([iv isKindOfClass:[NSData class]] && [(NSData *)iv length] == 0) return YES;
        if ([iv isKindOfClass:[NSString class]] && [(NSString *)iv length] == 0) return YES;
        return NO;
    }
    if (!iv) return NO;
    if ([iv isEqual:qv]) return YES;
    if ([iv isKindOfClass:[NSData class]] && [qv isKindOfClass:[NSString class]]) {
        return [(NSData *)iv isEqualToData:[(NSString *)qv dataUsingEncoding:NSUTF8StringEncoding]];
    }
    if ([iv isKindOfClass:[NSString class]] && [qv isKindOfClass:[NSData class]]) {
        return [[(NSString *)iv dataUsingEncoding:NSUTF8StringEncoding] isEqualToData:(NSData *)qv];
    }
    return NO;
}

static BOOL kcMatches(NSDictionary *item, NSDictionary *q) {
    NSData *pref = q[(__bridge id)kSecValuePersistentRef];
    if (pref && ![pref isEqual:[kcKey(item) dataUsingEncoding:NSUTF8StringEncoding]]) return NO;

    id qg = q[(__bridge id)kSecAttrAccessGroup];
    if ([qg isKindOfClass:[NSString class]] && [qg length]) {
        if (![normGroup(qg) isEqualToString:normGroup(item[(__bridge id)kSecAttrAccessGroup])]) return NO;
    }

    id qs = q[(__bridge id)kSecAttrSynchronizable];
    if (!qs) {
        if (itemSync(item)) return NO;
    } else if ([qs isKindOfClass:[NSNumber class]]) {
        if ([qs boolValue] != itemSync(item)) return NO;
    }

    // kSecAttrAccessible: cocokkan hanya jika item punya nilai tersimpan (kompatibel legacy)
    id qAcc = q[(__bridge id)kSecAttrAccessible];
    if (qAcc && item[(__bridge id)kSecAttrAccessible] && ![item[(__bridge id)kSecAttrAccessible] isEqual:qAcc]) {
        return NO;
    }

    NSArray *ks = @[
        (__bridge id)kSecClass, (__bridge id)kSecAttrService, (__bridge id)kSecAttrAccount,
        (__bridge id)kSecAttrLabel, (__bridge id)kSecAttrDescription, (__bridge id)kSecAttrComment,
        (__bridge id)kSecAttrCreator, (__bridge id)kSecAttrType, (__bridge id)kSecAttrApplicationLabel,
        (__bridge id)kSecAttrApplicationTag, (__bridge id)kSecAttrGeneric, (__bridge id)kSecAttrSecurityDomain,
        (__bridge id)kSecAttrServer, (__bridge id)kSecAttrProtocol, (__bridge id)kSecAttrAuthenticationType,
        (__bridge id)kSecAttrPort, (__bridge id)kSecAttrPath, (__bridge id)kSecAttrIsInvisible,
        (__bridge id)kSecAttrIsNegative,
    ];
    for (id k in ks) {
        id qv = q[k];
        if (!qv) continue;
        if (!attrEquals(item[k], qv)) return NO;
    }
    return YES;
}

static id kcFormat(NSDictionary *item, NSDictionary *q) {
    BOOL wData = [q[(__bridge id)kSecReturnData] boolValue];
    BOOL wAttr = [q[(__bridge id)kSecReturnAttributes] boolValue];
    BOOL wRef  = [q[(__bridge id)kSecReturnRef] boolValue];
    BOOL wPRef = [q[(__bridge id)kSecReturnPersistentRef] boolValue];
    if (!wData && !wAttr && !wRef && !wPRef) return nil;

    if (wData && !wAttr && !wRef && !wPRef) {
        return item[(__bridge id)kSecValueData] ?: [NSData data];
    }
    NSData *prefData = [kcKey(item) dataUsingEncoding:NSUTF8StringEncoding];
    if (wAttr) {
        NSMutableDictionary *m = [item mutableCopy];
        [m removeObjectForKey:@"_lc_hasAccessControl"];
        if (!wData) [m removeObjectForKey:(__bridge id)kSecValueData];
        else if (!m[(__bridge id)kSecValueData]) m[(__bridge id)kSecValueData] = [NSData data];
        if (wPRef) m[(__bridge id)kSecValuePersistentRef] = prefData;
        if (wRef)  m[(__bridge id)kSecValueRef] = prefData;
        return m;
    }
    return prefData;
}

// CRITICAL FIX v11 (K3): Kenali format persistentRef milik Fake Keychain meskipun itemnya sudah dihapus!
// Mencegah query persistentRef yang sudah terhapus jatuh ke Keychain asli iOS.
static BOOL isFakePersistentRefQuery(NSDictionary *q) {
    NSData *pref = q[(__bridge id)kSecValuePersistentRef];
    if (![pref isKindOfClass:[NSData class]] || pref.length < 5) return NO;
    NSString *key = [[NSString alloc] initWithData:pref encoding:NSUTF8StringEncoding];
    if (!key.length) return NO;
    if ([key hasPrefix:@"genp|"] || [key hasPrefix:@"inet|"]) return YES;
    @synchronized (gLock) {
        return kcStore()[key] != nil;
    }
}

static NSString *qdesc(NSDictionary *q) {
    return [NSString stringWithFormat:@"grp=%@ svc=%@ acc=%@",
            q[(__bridge id)kSecAttrAccessGroup] ?: @"-",
            q[(__bridge id)kSecAttrService] ?: @"-",
            q[(__bridge id)kSecAttrAccount] ?: @"-"];
}

static void logCFError(NSString *what, CFErrorRef e) {
    if (!e) { LCLog(@"[key] %@ GAGAL (tanpa detail error)", what); return; }
    LCLog(@"[key] %@ GAGAL code=%ld domain=%@", what, (long)CFErrorGetCode(e), (__bridge NSString *)CFErrorGetDomain(e));
}

static NSString *tagStr(id t) {
    if ([t isKindOfClass:[NSData class]]) {
        NSString *s = [[NSString alloc] initWithData:t encoding:NSUTF8StringEncoding];
        return s ?: [NSString stringWithFormat:@"<%lu byte>", (unsigned long)[t length]];
    }
    return t ? [NSString stringWithFormat:@"%@", t] : @"-";
}

static OSStatus my_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    NSDictionary *a = (__bridge NSDictionary *)attributes;
    if (a && isKeyClass(a)) {
        OSStatus st = orig_SecItemAdd((__bridge CFDictionaryRef)scopeKeyDict(a, YES), result);
        if (st == errSecSuccess) unscopeResult(result);
        LCLog(@"[key] SecItemAdd status=%d tag=%@", (int)st, tagStr(a[(__bridge id)kSecAttrApplicationTag]));
        return st;
    }
    if (a && isCertOrIdentityClass(a)) {
        OSStatus st = orig_SecItemAdd((__bridge CFDictionaryRef)scopeCertDict(a, YES), result);
        if (st == errSecSuccess) unscopeResult(result);
        return st;
    }
    if (!a || !isPasswordClass(a)) {
        if (!a) return orig_SecItemAdd(attributes, result);
        NSMutableDictionary *m = [a mutableCopy];
        stripForeignAccessGroup(m);
        return orig_SecItemAdd((__bridge CFDictionaryRef)m, result);
    }
    @synchronized (gLock) {
        NSMutableDictionary *kc = kcStore();
        NSString *key = kcKey(a);
        if (kc[key]) { LCLog(@"Add DUPLICATE %@", key); return errSecDuplicateItem; }
        NSMutableDictionary *item = sanitize(a);
        item[(__bridge id)kSecAttrAccessGroup] = normGroup(a[(__bridge id)kSecAttrAccessGroup]);
        item[(__bridge id)kSecAttrSynchronizable] = @(itemSync(a));
        if (!item[(__bridge id)kSecValueData]) item[(__bridge id)kSecValueData] = [NSData data];
        NSDate *now = [NSDate date];
        item[(__bridge id)kSecAttrCreationDate] = now;
        item[(__bridge id)kSecAttrModificationDate] = now;
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
    if (!q) return orig_SecItemCopyMatching(query, result);

    BOOL isFakePRef = isFakePersistentRefQuery(q);
    if (!isFakePRef && isKeyClass(q)) {
        BOOL hasDirectLookup = (q[(__bridge id)kSecAttrApplicationTag] != nil ||
                                q[(__bridge id)kSecValuePersistentRef] != nil ||
                                q[(__bridge id)kSecValueRef] != nil);
        OSStatus st;
        if (hasDirectLookup) {
            st = orig_SecItemCopyMatching((__bridge CFDictionaryRef)scopeKeyDict(q, NO), result);
            if (st == errSecSuccess) unscopeResult(result);
        } else {
            st = filteredRealCopyMatching(q, result, NO);
        }
        LCLog(@"[key] SecItemCopyMatching status=%d tag=%@", (int)st, tagStr(q[(__bridge id)kSecAttrApplicationTag]));
        return st;
    }
    if (!isFakePRef && isCertOrIdentityClass(q)) {
        BOOL hasDirectLookup = (q[(__bridge id)kSecAttrLabel] != nil ||
                                q[(__bridge id)kSecValuePersistentRef] != nil ||
                                q[(__bridge id)kSecValueRef] != nil);
        if (hasDirectLookup) {
            OSStatus st = orig_SecItemCopyMatching((__bridge CFDictionaryRef)scopeCertDict(q, NO), result);
            if (st == errSecSuccess) unscopeResult(result);
            return st;
        }
        return filteredRealCopyMatching(q, result, YES);
    }
    if (!isFakePRef && !isPasswordClass(q)) {
        NSMutableDictionary *m = [q mutableCopy];
        stripForeignAccessGroup(m);
        return orig_SecItemCopyMatching((__bridge CFDictionaryRef)m, result);
    }

    @synchronized (gLock) {
        NSMutableArray<NSDictionary *> *hits = [NSMutableArray array];
        for (NSString *k in kcStore()) {
            if (kcMatches(gKC[k], q)) [hits addObject:gKC[k]];
        }
        if (!hits.count) {
            LCLog(@"Copy NOT FOUND %@", qdesc(q));
            return errSecItemNotFound;
        }
        // Urutkan deterministik berdasarkan prioritas 3 access group GoPay lalu tanggal modifikasi.
        [hits sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
            NSInteger pa = groupPriority(normGroup(a[(__bridge id)kSecAttrAccessGroup]));
            NSInteger pb = groupPriority(normGroup(b[(__bridge id)kSecAttrAccessGroup]));
            if (pa != pb) return pa < pb ? NSOrderedAscending : NSOrderedDescending;
            NSDate *da = a[(__bridge id)kSecAttrModificationDate] ?: [NSDate distantPast];
            NSDate *db = b[(__bridge id)kSecAttrModificationDate] ?: [NSDate distantPast];
            return [db compare:da];
        }];

        id lim = q[(__bridge id)kSecMatchLimit];
        BOOL wantMany = [lim isEqual:(__bridge id)kSecMatchLimitAll] ||
                        ([lim isKindOfClass:[NSNumber class]] && [lim integerValue] > 1);
        if (result) {
            if (wantMany) {
                NSInteger cap = [lim isKindOfClass:[NSNumber class]] ? [lim integerValue] : (NSInteger)hits.count;
                NSMutableArray *out = [NSMutableArray array];
                for (NSInteger i = 0; i < (NSInteger)hits.count && i < cap; i++) {
                    id f = kcFormat(hits[i], q);
                    if (f) [out addObject:f];
                }
                *result = out.count ? CFRetain((__bridge CFTypeRef)out) : NULL;
            } else {
                id f = kcFormat(hits[0], q);
                *result = f ? CFRetain((__bridge CFTypeRef)f) : NULL;
            }
        }
        LCLog(@"Copy OK count=%lu %@", (unsigned long)hits.count, qdesc(q));
        return errSecSuccess;
    }
}

static OSStatus my_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attrsToUpdate) {
    NSDictionary *q = (__bridge NSDictionary *)query;
    NSDictionary *upd = (__bridge NSDictionary *)attrsToUpdate;
    if (!q) return orig_SecItemUpdate(query, attrsToUpdate);

    BOOL isFakePRef = isFakePersistentRefQuery(q);
    if (!isFakePRef && isKeyClass(q)) {
        BOOL hasDirectLookup = (q[(__bridge id)kSecAttrApplicationTag] != nil ||
                                q[(__bridge id)kSecValuePersistentRef] != nil ||
                                q[(__bridge id)kSecValueRef] != nil);
        OSStatus st = hasDirectLookup
            ? orig_SecItemUpdate((__bridge CFDictionaryRef)scopeKeyDict(q, NO),
                                 upd ? (__bridge CFDictionaryRef)scopeKeyDict(upd, NO) : NULL)
            : filteredRealUpdate(q, upd, NO);
        LCLog(@"[key] SecItemUpdate status=%d tag=%@", (int)st, tagStr(q[(__bridge id)kSecAttrApplicationTag]));
        return st;
    }
    if (!isFakePRef && isCertOrIdentityClass(q)) {
        BOOL hasDirectLookup = (q[(__bridge id)kSecAttrLabel] != nil ||
                                q[(__bridge id)kSecValuePersistentRef] != nil ||
                                q[(__bridge id)kSecValueRef] != nil);
        return hasDirectLookup
            ? orig_SecItemUpdate((__bridge CFDictionaryRef)scopeCertDict(q, NO),
                                 upd ? (__bridge CFDictionaryRef)scopeCertDict(upd, NO) : NULL)
            : filteredRealUpdate(q, upd, YES);
    }
    if (!isFakePRef && !isPasswordClass(q)) {
        NSMutableDictionary *mq = [q mutableCopy]; stripForeignAccessGroup(mq);
        NSMutableDictionary *mu = upd ? [upd mutableCopy] : nil; if (mu) stripForeignAccessGroup(mu);
        return orig_SecItemUpdate((__bridge CFDictionaryRef)mq, mu ? (__bridge CFDictionaryRef)mu : NULL);
    }
    if (!upd) return errSecParam;

    @synchronized (gLock) {
        NSMutableDictionary *kc = kcStore();
        NSMutableArray<NSString *> *keys = [NSMutableArray array];
        for (NSString *k in kc) if (kcMatches(kc[k], q)) [keys addObject:k];
        if (!keys.count) return errSecItemNotFound;

        NSSet *matchedSet = [NSSet setWithArray:keys];
        NSMutableDictionary *sanUpd = sanitize(upd);
        if (upd[(__bridge id)kSecAttrAccessGroup]) {
            sanUpd[(__bridge id)kSecAttrAccessGroup] = normGroup(upd[(__bridge id)kSecAttrAccessGroup]);
        }

        // Cek duplicate collision sebelum mutasi
        NSMutableArray<NSDictionary *> *planned = [NSMutableArray arrayWithCapacity:keys.count];
        NSMutableSet *newKeysSeen = [NSMutableSet set];
        for (NSString *oldK in keys) {
            NSMutableDictionary *item = [kc[oldK] mutableCopy];
            [item addEntriesFromDictionary:sanUpd];
            item[(__bridge id)kSecAttrModificationDate] = [NSDate date];
            NSString *newK = kcKey(item);
            if ((![newK isEqualToString:oldK] && kc[newK] && ![matchedSet containsObject:newK]) ||
                [newKeysSeen containsObject:newK]) {
                return errSecDuplicateItem;
            }
            [newKeysSeen addObject:newK];
            [planned addObject:@{ @"old": oldK, @"new": newK, @"item": item }];
        }
        for (NSDictionary *p in planned) [kc removeObjectForKey:p[@"old"]];
        for (NSDictionary *p in planned) kc[p[@"new"]] = p[@"item"];
        kcSave();
        LCLog(@"Update OK count=%lu %@", (unsigned long)keys.count, qdesc(q));
    }
    return errSecSuccess;
}

static OSStatus my_SecItemDelete(CFDictionaryRef query) {
    NSDictionary *q = (__bridge NSDictionary *)query;
    if (!q) return orig_SecItemDelete(query);

    BOOL isFakePRef = isFakePersistentRefQuery(q);
    if (!isFakePRef && isKeyClass(q)) {
        BOOL hasDirectLookup = (q[(__bridge id)kSecAttrApplicationTag] != nil ||
                                q[(__bridge id)kSecValuePersistentRef] != nil ||
                                q[(__bridge id)kSecValueRef] != nil);
        OSStatus st = hasDirectLookup
            ? orig_SecItemDelete((__bridge CFDictionaryRef)scopeKeyDict(q, NO))
            : filteredRealDelete(q, NO);
        LCLog(@"[key] SecItemDelete status=%d tag=%@", (int)st, tagStr(q[(__bridge id)kSecAttrApplicationTag]));
        return st;
    }
    if (!isFakePRef && isCertOrIdentityClass(q)) {
        BOOL hasDirectLookup = (q[(__bridge id)kSecAttrLabel] != nil ||
                                q[(__bridge id)kSecValuePersistentRef] != nil ||
                                q[(__bridge id)kSecValueRef] != nil);
        return hasDirectLookup
            ? orig_SecItemDelete((__bridge CFDictionaryRef)scopeCertDict(q, NO))
            : filteredRealDelete(q, YES);
    }
    if (!isFakePRef && !isPasswordClass(q)) {
        NSMutableDictionary *m = [q mutableCopy];
        stripForeignAccessGroup(m);
        return orig_SecItemDelete((__bridge CFDictionaryRef)m);
    }

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
    BOOL se = [p[(__bridge id)kSecAttrTokenID] isEqual:(__bridge id)kSecAttrTokenIDSecureEnclave];
    CFErrorRef local = NULL;
    SecKeyRef k = orig_SecKeyCreateRandomKey((__bridge CFDictionaryRef)scopeKeyParams(p, YES), error ? error : &local);
    NSString *tag = [NSString stringWithFormat:@"SecKeyCreateRandomKey(secureEnclave=%@)", se ? @"YA" : @"tidak"];
    if (k) LCLog(@"[key] %@ OK", tag);
    else logCFError(tag, error ? *error : local);
    if (local) CFRelease(local);
    return k;
}

// Dipakai oleh GotoUtils.framework (CryptoRSAManager)
static OSStatus my_SecKeyGeneratePair(CFDictionaryRef params, SecKeyRef *pubKey, SecKeyRef *privKey) {
    NSDictionary *p = (__bridge NSDictionary *)params;
    if (!p) return orig_SecKeyGeneratePair(params, pubKey, privKey);
    OSStatus st = orig_SecKeyGeneratePair((__bridge CFDictionaryRef)scopeKeyParams(p, YES), pubKey, privKey);
    LCLog(@"[key] SecKeyGeneratePair status=%d", (int)st);
    return st;
}

static CFDictionaryRef my_SecKeyCopyAttributes(SecKeyRef key) {
    CFDictionaryRef raw = orig_SecKeyCopyAttributes(key);
    if (!raw) return NULL;
    NSDictionary *d = CFBridgingRelease(raw);
    NSDictionary *clean = unscopeObj(d);
    return (__bridge_retained CFDictionaryRef)clean;
}

#pragma mark - 9. Diagnostik Key / Biometrik (dengan dedup/throttle anti-spam)

static CFDataRef (*orig_SecKeyCreateEncryptedData)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);
static CFDataRef (*orig_SecKeyCreateDecryptedData)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);
static CFDataRef (*orig_SecKeyCreateSignature)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);

#define LC_KEYOP(NAME, ORIG) \
static CFDataRef NAME(SecKeyRef key, SecKeyAlgorithm alg, CFDataRef data, CFErrorRef *error) { \
    CFErrorRef local = NULL; \
    CFDataRef r = ORIG(key, alg, data, error ? error : &local); \
    if (r) LCLog(@"[key] " #NAME " OK"); else logCFError(@"" #NAME, error ? *error : local); \
    if (local) CFRelease(local); \
    return r; \
}
LC_KEYOP(my_SecKeyCreateEncryptedData, orig_SecKeyCreateEncryptedData)
LC_KEYOP(my_SecKeyCreateDecryptedData, orig_SecKeyCreateDecryptedData)
LC_KEYOP(my_SecKeyCreateSignature, orig_SecKeyCreateSignature)
#endif

#if LC_TRACE_AUTH
static NSObject *gAuthLogLock;
static NSInteger gLastLAPolicy = -999;
static BOOL gLastLAResult = NO;
static NSInteger gLastLAErr = -999;
static CFAbsoluteTime gLastLALogTime = 0;
static NSUInteger gSuppressedLACount = 0;

static BOOL (*orig_laCan)(id, SEL, NSInteger, NSError * __autoreleasing *);
static BOOL my_laCan(id self, SEL _cmd, NSInteger policy, NSError * __autoreleasing *err) {
    NSError * __autoreleasing local = nil;
    BOOL r = orig_laCan(self, _cmd, policy, err ? err : &local);
    NSError *e = r ? nil : (err ? *err : local);
    NSInteger code = e ? e.code : 0;

    BOOL shouldLog = NO;
    NSUInteger suppressed = 0;
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    @synchronized (gAuthLogLock) {
        BOOL changed = (policy != gLastLAPolicy || r != gLastLAResult || code != gLastLAErr);
        if (changed || (now - gLastLALogTime) >= 10.0) {
            shouldLog = YES;
            suppressed = gSuppressedLACount;
            gSuppressedLACount = 0;
            gLastLAPolicy = policy;
            gLastLAResult = r;
            gLastLAErr = code;
            gLastLALogTime = now;
        } else {
            gSuppressedLACount++;
        }
    }
    if (shouldLog) {
        if (suppressed > 0) {
            LCLog(@"LAContext canEvaluatePolicy policy=%ld -> %@ errcode=%ld (suppressed=%lu)",
                  (long)policy, r ? @"YA" : @"TIDAK", (long)code, (unsigned long)suppressed);
        } else {
            LCLog(@"LAContext canEvaluatePolicy policy=%ld -> %@ errcode=%ld",
                  (long)policy, r ? @"YA" : @"TIDAK", (long)code);
        }
    }
    return r;
}

static void (*orig_laEval)(id, SEL, NSInteger, NSString *, void (^)(BOOL, NSError *));
static void my_laEval(id self, SEL _cmd, NSInteger policy, NSString *reason, void (^reply)(BOOL, NSError *)) {
    LCLog(@"LAContext evaluatePolicy policy=%ld dimulai", (long)policy);
    orig_laEval(self, _cmd, policy, reason, ^(BOOL ok, NSError *e) {
        LCLog(@"LAContext evaluatePolicy -> %@ errcode=%ld", ok ? @"BERHASIL" : @"GAGAL", (long)(e ? e.code : 0));
        if (reply) reply(ok, e);
    });
}

static void installAuthTraceIfLoaded(void) {
    Class la = NSClassFromString(@"LAContext");
    if (!la) return;
    hookInstanceMethod(la, NSSelectorFromString(@"canEvaluatePolicy:error:"),
                       (IMP)my_laCan, (IMP *)&orig_laCan);
    hookInstanceMethod(la, NSSelectorFromString(@"evaluatePolicy:localizedReason:reply:"),
                       (IMP)my_laEval, (IMP *)&orig_laEval);
}

static void logPermissionStatusOnce(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Class cn = NSClassFromString(@"CNContactStore");
        if (cn) {
            NSInteger st = ((NSInteger (*)(Class, SEL, NSInteger))objc_msgSend)(
                cn, NSSelectorFromString(@"authorizationStatusForEntityType:"), 0);
            LCLog(@"izin Kontak status=%ld", (long)st);
        }
        Class cl = NSClassFromString(@"CLLocationManager");
        if (cl) {
            int st = ((int (*)(Class, SEL))objc_msgSend)(cl, NSSelectorFromString(@"authorizationStatus"));
            LCLog(@"izin Lokasi status=%d", st);
        }
    });
}
#endif

#pragma mark - Diagnostik Image Loading & Deferred Hooks

static void logLoadedKeyFrameworksOnce(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        uint32_t total = _dyld_image_count();
        NSArray<NSString *> *watch = @[
            @"GoPay.app/GoPay",
            @"flutter_inappwebview_ios",
            @"flutter_secure_storage_darwin",
            @"GotoLoginSSO",
            @"GotoNetworking",
            @"GoogleUtilities",
            @"FirebaseInstallations",
            @"tagihan_unified_emoney",
        ];
        NSMutableArray<NSString *> *found = [NSMutableArray array];
        for (uint32_t i = 0; i < total; i++) {
            const char *name = _dyld_get_image_name(i);
            if (!name) continue;
            NSString *s = [NSString stringWithUTF8String:name];
            for (NSString *w in watch) {
                if ([s containsString:w]) {
                    [found addObject:w];
                }
            }
        }
        LCLog(@"dyld images=%u matched=%@", total, [found componentsJoinedByString:@","]);
    });
}

static void installDeferredHooks(void) {
#if LC_ENABLE_SWIZZLE
#if LC_ISOLATE_WEB_NET
    // Pre-warm di main thread sebelum Flutter/WebView dimulai (mencegah deadlock dispatch_sync).
    (void)isolatedStore();
    (void)isolatedRuleListStore();
    (void)isolatedSharedSession();
#endif
#if LC_ISOLATE_PREFS
    (void)detectStandardPersistentDomainMode();
#endif
#if LC_ISOLATE_DEVICE_IDS
    installAdSupportHookIfLoaded();
#endif
#if LC_PASTEBOARD_MODE > 0
    // Pastikan subclass class cluster (_UIConcretePasteboard) ikut ter-hook
    installPasteboardHooksOnClass([UIPasteboard generalPasteboard].class);
#endif
#if LC_ISOLATE_NOTIFICATIONS || LC_ISOLATE_SYSTEM_UI
    installNotificationHooksIfLoaded();
#endif
    installBrowserHooksIfLoaded();
#if LC_ISOLATE_WEB_NET
    installAppDelegateBgHookIfReady();
#endif
#endif
#if LC_TRACE_AUTH
    installAuthTraceIfLoaded();
    logPermissionStatusOnce();
#endif
}

#pragma mark - Init

__attribute__((constructor))
static void lc_init(void) {
    gLogLock = [NSObject new];
    gCIDLock = [NSObject new];
#if LC_ISOLATE_DEVICE_IDS
    gIDFVLock = [NSObject new];
#endif
#if LC_ENABLE_KEYCHAIN
    gLock = [NSObject new];
#endif
#if LC_ISOLATE_WEB_NET
    gNetLock = [NSObject new];
#endif
#if LC_PASTEBOARD_MODE > 0
    gPBLock = [NSObject new];
    gPBItems = [NSMutableArray array];
#endif
#if LC_ISOLATE_SYSTEM_UI
    gSysUILock = [NSObject new];
#endif
#if LC_TRACE_AUTH
    gAuthLogLock = [NSObject new];
#endif

    LCLog(@"=== init v11 home=%@ pbMode=%d", NSHomeDirectory(), LC_PASTEBOARD_MODE);

#if LC_CRASH_LOG
    gPrevUncaughtHandler = NSGetUncaughtExceptionHandler();
    NSSetUncaughtExceptionHandler(&crashException);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crashSignal;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    for (size_t i = 0; i < sizeof(gCrashSigs) / sizeof(gCrashSigs[0]); i++) {
        sigaction(gCrashSigs[i], &sa, &gPrevSigActions[i]);
    }
#endif

#if LC_ENABLE_SWIZZLE
    // 1. App Group FileManager
    hookInstanceMethod([NSFileManager class],
                       @selector(containerURLForSecurityApplicationGroupIdentifier:),
                       (IMP)my_containerURLForGroup, (IMP *)&orig_containerURLForGroup);

#if LC_ISOLATE_DEVICE_IDS
    hookInstanceMethod([UIDevice class], @selector(identifierForVendor),
                       (IMP)my_identifierForVendor, (IMP *)&orig_identifierForVendor);
    hookInstanceMethod([UIDevice class], @selector(name),
                       (IMP)my_deviceName, (IMP *)&orig_deviceName);
    hookInstanceMethod([NSProcessInfo class], @selector(hostName),
                       (IMP)my_hostName, (IMP *)&orig_hostName);
    installAdSupportHookIfLoaded();
#endif

#if LC_ISOLATE_PREFS
    hookInstanceMethod([NSUserDefaults class], @selector(initWithSuiteName:),
                       (IMP)my_udInitWithSuiteName, (IMP *)&orig_udInitWithSuiteName);
    hookInstanceMethod([NSUserDefaults class], @selector(addSuiteNamed:),
                       (IMP)my_udAddSuite, (IMP *)&orig_udAddSuite);
    hookInstanceMethod([NSUserDefaults class], @selector(removeSuiteNamed:),
                       (IMP)my_udRemoveSuite, (IMP *)&orig_udRemoveSuite);
    hookInstanceMethod([NSUserDefaults class], @selector(persistentDomainForName:),
                       (IMP)my_udPersistentDomain, (IMP *)&orig_udPersistentDomain);
    hookInstanceMethod([NSUserDefaults class], @selector(setPersistentDomain:forName:),
                       (IMP)my_udSetPersistentDomain, (IMP *)&orig_udSetPersistentDomain);
    hookInstanceMethod([NSUserDefaults class], @selector(removePersistentDomainForName:),
                       (IMP)my_udRemovePersistentDomain, (IMP *)&orig_udRemovePersistentDomain);
#endif

#if LC_ISOLATE_WEB_NET
    hookClassMethod([NSHTTPCookieStorage class], @selector(sharedHTTPCookieStorage),
                    (IMP)my_sharedHTTPCookieStorage, (IMP *)&orig_sharedHTTPCookieStorage);
    hookClassMethod([NSHTTPCookieStorage class], @selector(sharedCookieStorageForGroupContainerIdentifier:),
                    (IMP)my_sharedCookieStorageForGroup, (IMP *)&orig_sharedCookieStorageForGroup);
    hookClassMethod([NSURLCache class], @selector(sharedURLCache),
                    (IMP)my_sharedURLCache, (IMP *)&orig_sharedURLCache);
    hookClassMethod([NSURLCache class], @selector(setSharedURLCache:),
                    (IMP)my_setSharedURLCache, (IMP *)&orig_setSharedURLCache);
    hookClassMethod([NSURLCredentialStorage class], @selector(sharedCredentialStorage),
                    (IMP)my_sharedCredentialStorage, (IMP *)&orig_sharedCredentialStorage);
    hookClassMethod([NSURLSession class], @selector(sharedSession),
                    (IMP)my_sharedSession, (IMP *)&orig_sharedSession);
    hookClassMethod([NSURLSessionConfiguration class], @selector(defaultSessionConfiguration),
                    (IMP)my_defaultSessionConfig, (IMP *)&orig_defaultSessionConfig);
    hookClassMethod([NSURLSessionConfiguration class], @selector(backgroundSessionConfigurationWithIdentifier:),
                    (IMP)my_bgSessionConfig, (IMP *)&orig_bgSessionConfig);
    if (class_getClassMethod([NSURLSessionConfiguration class], NSSelectorFromString(@"backgroundSessionConfiguration:"))) {
        hookClassMethod([NSURLSessionConfiguration class], NSSelectorFromString(@"backgroundSessionConfiguration:"),
                        (IMP)my_bgSessionConfigLegacy, (IMP *)&orig_bgSessionConfigLegacy);
    }

    hookClassMethod([WKWebsiteDataStore class], @selector(defaultDataStore),
                    (IMP)my_wkDefaultDataStore, (IMP *)&orig_wkDefaultDataStore);
    hookClassMethod([WKContentRuleListStore class], @selector(defaultStore),
                    (IMP)my_wkRuleListDefaultStore, (IMP *)&orig_wkRuleListDefaultStore);
    hookInstanceMethod([WKWebViewConfiguration class], @selector(init),
                       (IMP)my_wkCfgInit, (IMP *)&orig_wkCfgInit);
    hookInstanceMethod([WKWebViewConfiguration class], @selector(initWithCoder:),
                       (IMP)my_wkCfgInitCoder, (IMP *)&orig_wkCfgInitCoder);
    hookInstanceMethod([WKWebViewConfiguration class], @selector(copyWithZone:),
                       (IMP)my_wkCfgCopyWithZone, (IMP *)&orig_wkCfgCopyWithZone);
    hookInstanceMethod([WKWebViewConfiguration class], @selector(setWebsiteDataStore:),
                       (IMP)my_wkCfgSetStore, (IMP *)&orig_wkCfgSetStore);
    hookInstanceMethod([WKWebView class], @selector(initWithFrame:configuration:),
                       (IMP)my_wkInitFrameCfg, (IMP *)&orig_wkInitFrameCfg);
    hookInstanceMethod([WKWebView class], @selector(initWithCoder:),
                       (IMP)my_wkInitCoder, (IMP *)&orig_wkInitCoder);
#endif

#if LC_PASTEBOARD_MODE > 0
    hookClassMethod([UIPasteboard class], @selector(pasteboardWithName:create:),
                    (IMP)my_pbWithName, (IMP *)&orig_pbWithName);
    Class concretePB = NSClassFromString(@"_UIConcretePasteboard");
    installPasteboardHooksOnClass(concretePB ?: [UIPasteboard class]);
#endif

#if LC_ISOLATE_SYSTEM_UI
    hookInstanceMethod([UIApplication class], @selector(setShortcutItems:),
                       (IMP)my_setShortcutItems, (IMP *)&orig_setShortcutItems);
    hookInstanceMethod([UIApplication class], @selector(shortcutItems),
                       (IMP)my_shortcutItems, (IMP *)&orig_shortcutItems);
    hookInstanceMethod([UIApplication class], @selector(setApplicationIconBadgeNumber:),
                       (IMP)my_setAppBadge, (IMP *)&orig_setAppBadge);
    hookInstanceMethod([UIApplication class], @selector(applicationIconBadgeNumber),
                       (IMP)my_appBadge, (IMP *)&orig_appBadge);
#endif

#if LC_ISOLATE_NOTIFICATIONS || LC_ISOLATE_SYSTEM_UI
    installNotificationHooksIfLoaded();
#endif
    installBrowserHooksIfLoaded();
#endif

#if LC_TRACE_WEB
    hookInstanceMethod([WKWebView class], @selector(loadRequest:),
                       (IMP)my_wkLoadRequest, (IMP *)&orig_wkLoadRequest);
    hookInstanceMethod([WKWebView class], @selector(loadHTMLString:baseURL:),
                       (IMP)my_wkLoadHTML, (IMP *)&orig_wkLoadHTML);
    hookInstanceMethod([WKWebView class], @selector(loadFileURL:allowingReadAccessToURL:),
                       (IMP)my_wkLoadFile, (IMP *)&orig_wkLoadFile);
    hookInstanceMethod([WKHTTPCookieStore class], @selector(setCookie:completionHandler:),
                       (IMP)my_wkSetCookie, (IMP *)&orig_wkSetCookie);
    hookInstanceMethod([WKHTTPCookieStore class], @selector(deleteCookie:completionHandler:),
                       (IMP)my_wkDeleteCookie, (IMP *)&orig_wkDeleteCookie);
    hookInstanceMethod([WKWebsiteDataStore class], @selector(removeDataOfTypes:modifiedSince:completionHandler:),
                       (IMP)my_wkRemoveDataSince, (IMP *)&orig_wkRemoveDataSince);
    hookInstanceMethod([WKUserContentController class], @selector(addScriptMessageHandler:name:),
                       (IMP)my_wkAddMsgHandler, (IMP *)&orig_wkAddMsgHandler);
    if (class_getInstanceMethod([WKUserContentController class],
                                NSSelectorFromString(@"addScriptMessageHandler:contentWorld:name:"))) {
        hookInstanceMethod([WKUserContentController class],
                           NSSelectorFromString(@"addScriptMessageHandler:contentWorld:name:"),
                           (IMP)my_wkAddMsgHandlerWorld, (IMP *)&orig_wkAddMsgHandlerWorld);
    }
    hookInstanceMethod([UIApplication class], @selector(openURL:options:completionHandler:),
                       (IMP)my_appOpenURL, (IMP *)&orig_appOpenURL);
#elif LC_ISOLATE_WEB_NET && LC_WEBVIEW_IOS16_ISOLATE
    hookInstanceMethod([WKHTTPCookieStore class], @selector(setCookie:completionHandler:),
                       (IMP)my_wkSetCookie, (IMP *)&orig_wkSetCookie);
    hookInstanceMethod([WKHTTPCookieStore class], @selector(deleteCookie:completionHandler:),
                       (IMP)my_wkDeleteCookie, (IMP *)&orig_wkDeleteCookie);
#endif

#if LC_TRACE_AUTH
    installAuthTraceIfLoaded();
#endif

    // Hook C symbols via fishhook (hanya sekali, mencakup semua image yang sudah & akan dimuat)
    struct rebinding rebs[24];
    size_t count = 0;
#if LC_ENABLE_KEYCHAIN
    rebs[count++] = (struct rebinding){"SecItemAdd",                (void *)my_SecItemAdd,                (void **)&orig_SecItemAdd};
    rebs[count++] = (struct rebinding){"SecItemCopyMatching",       (void *)my_SecItemCopyMatching,       (void **)&orig_SecItemCopyMatching};
    rebs[count++] = (struct rebinding){"SecItemUpdate",             (void *)my_SecItemUpdate,             (void **)&orig_SecItemUpdate};
    rebs[count++] = (struct rebinding){"SecItemDelete",             (void *)my_SecItemDelete,             (void **)&orig_SecItemDelete};
    rebs[count++] = (struct rebinding){"SecKeyCreateRandomKey",     (void *)my_SecKeyCreateRandomKey,     (void **)&orig_SecKeyCreateRandomKey};
    rebs[count++] = (struct rebinding){"SecKeyGeneratePair",        (void *)my_SecKeyGeneratePair,        (void **)&orig_SecKeyGeneratePair};
    rebs[count++] = (struct rebinding){"SecKeyCopyAttributes",      (void *)my_SecKeyCopyAttributes,      (void **)&orig_SecKeyCopyAttributes};
    rebs[count++] = (struct rebinding){"SecKeyCreateEncryptedData", (void *)my_SecKeyCreateEncryptedData, (void **)&orig_SecKeyCreateEncryptedData};
    rebs[count++] = (struct rebinding){"SecKeyCreateDecryptedData", (void *)my_SecKeyCreateDecryptedData, (void **)&orig_SecKeyCreateDecryptedData};
    rebs[count++] = (struct rebinding){"SecKeyCreateSignature",     (void *)my_SecKeyCreateSignature,     (void **)&orig_SecKeyCreateSignature};
#endif
#if LC_ISOLATE_PREFS
    rebs[count++] = (struct rebinding){"CFPreferencesCopyAppValue",                  (void *)my_CFPreferencesCopyAppValue,                  (void **)&orig_CFPreferencesCopyAppValue};
    rebs[count++] = (struct rebinding){"CFPreferencesSetAppValue",                   (void *)my_CFPreferencesSetAppValue,                   (void **)&orig_CFPreferencesSetAppValue};
    rebs[count++] = (struct rebinding){"CFPreferencesCopyKeyList",                   (void *)my_CFPreferencesCopyKeyList,                   (void **)&orig_CFPreferencesCopyKeyList};
    rebs[count++] = (struct rebinding){"CFPreferencesSetMultiple",                   (void *)my_CFPreferencesSetMultiple,                   (void **)&orig_CFPreferencesSetMultiple};
    rebs[count++] = (struct rebinding){"CFPreferencesAppSynchronize",                (void *)my_CFPreferencesAppSynchronize,                (void **)&orig_CFPreferencesAppSynchronize};
    rebs[count++] = (struct rebinding){"CFPreferencesRemoveSuitePreferencesFromApp", (void *)my_CFPreferencesRemoveSuitePreferencesFromApp, (void **)&orig_CFPreferencesRemoveSuitePreferencesFromApp};
#endif
#if LC_ISOLATE_DEVICE_IDS
    rebs[count++] = (struct rebinding){"gethostname", (void *)my_gethostname, (void **)&orig_gethostname};
#endif
    if (count > 0) {
        int rc = rebind_symbols(rebs, count);
        LCLog(@"rebind_symbols count=%zu rc=%d", count, rc);
    }

    // Hook framework opsional & pre-warm WebKit seawal mungkin di main thread.
    dispatch_async(dispatch_get_main_queue(), ^{
        installDeferredHooks();
    });
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc addObserverForName:UIApplicationWillFinishLaunchingNotification
                    object:nil
                     queue:[NSOperationQueue mainQueue]
                usingBlock:^(NSNotification *n) {
        (void)n;
        refreshLogFile(NO);
        installDeferredHooks();
    }];
    [nc addObserverForName:UIApplicationDidFinishLaunchingNotification
                    object:nil
                     queue:[NSOperationQueue mainQueue]
                usingBlock:^(NSNotification *n) {
        (void)n;
        refreshLogFile(YES);
        LCLog(@"DidFinishLaunching container=%@ home=%@", getContainerID(), NSHomeDirectory());
        installDeferredHooks();
        logLoadedKeyFrameworksOnce();
    }];
#if LC_PASTEBOARD_MODE > 0
    [nc addObserverForName:UIApplicationDidBecomeActiveNotification
                    object:nil
                     queue:nil
                usingBlock:^(NSNotification *n) {
        (void)n;
        atomic_store_explicit(&gAppIsActive, YES, memory_order_relaxed);
    }];
    [nc addObserverForName:UIApplicationWillResignActiveNotification
                    object:nil
                     queue:nil
                usingBlock:^(NSNotification *n) {
        (void)n;
        atomic_store_explicit(&gAppIsActive, NO, memory_order_relaxed);
    }];
    [nc addObserverForName:UIApplicationDidEnterBackgroundNotification
                    object:nil
                     queue:nil
                usingBlock:^(NSNotification *n) {
        (void)n;
        atomic_store_explicit(&gAppIsActive, NO, memory_order_relaxed);
    }];
#endif
#if LC_ISOLATE_WEB_NET
    [nc addObserverForName:UIApplicationWillResignActiveNotification
                    object:nil
                     queue:nil
                usingBlock:^(NSNotification *n) {
        (void)n;
        persistIsolatedCookiesNow();
    }];
    [nc addObserverForName:UIApplicationDidEnterBackgroundNotification
                    object:nil
                     queue:nil
                usingBlock:^(NSNotification *n) {
        (void)n;
        persistIsolatedCookiesNow();
    }];
#endif

    LCLog(@"=== init v11 selesai");
}
