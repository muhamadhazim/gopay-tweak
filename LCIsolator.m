#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <Security/Security.h>
#import <CoreFoundation/CoreFoundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <signal.h>
#import <execinfo.h>
#import <fcntl.h>
#import <unistd.h>
#import "fishhook.h"

// ============================================================================
// LCIsolator v10 — Deep Container Isolation untuk GoPay di LiveContainer
// Saklar bisecting: matikan satu per satu (0) jika ingin uji A/B.
// ============================================================================
#define LC_ENABLE_SWIZZLE           1
#define LC_ENABLE_KEYCHAIN          1
#define LC_ISOLATE_PREFS            1   // NSUserDefaults (6 method domain) + CFPreferences* (non-Apple)
#define LC_ISOLATE_WEB_NET          1   // NSHTTPCookieStorage, NSURLCache, NSURLCredentialStorage, NSURLSessionConfiguration, WKWebViewConfiguration, WKProcessPool
#define LC_FORCE_WEBVIEW_STORE      1   // Paksa WKWebsiteDataStore container di WKWebViewConfiguration & WKWebView
#define LC_WEBVIEW_IOS16_NONPERSIST 0   // 1 = fallback nonPersistentDataStore di iOS <17 (cookie tetap via NSHTTPCookieStorage)
#define LC_EPHEMERAL_WEBAUTH        1   // Paksa ASWebAuthenticationSession.prefersEphemeralWebBrowserSession = YES
#define LC_PASTEBOARD_MODE          1   // 0=off, 1=isolasi in-container (copy-paste internal jalan), 2=blokir total
#define LC_ISOLATE_NOTIFICATIONS    1   // Isolasi UNUserNotificationCenter per container
#define LC_ISOLATE_DEVICE_IDS       1   // IDFV, IDFA (zero UUID), UIDevice.name, NSProcessInfo.hostName
#define LC_CRASH_LOG                1   // Chained sigaction + uncaught exception logger (tidak menimpa Crashlytics/Flutter)
#define LC_TRACE_WEB                1   // Log diagnostik jalur WebView/browser (tanpa nilai cookie/token)
#define LC_TRACE_AUTH               1   // Log diagnostik LAContext (Face ID/PIN) & status izin

// Access group default = group PERTAMA di entitlement GoPay (tanpa prefix Team ID).
#define LC_DEFAULT_KC_GROUP @"gojekSharedKeychain"

#pragma mark - Logging (lazy & thread-safe, tidak mengunci NSHomeDirectory terlalu dini)

static int gLogFD = -1;
static NSObject *gLogLock;
static NSString *gLogHomeSnapshot;

static void ensureLogFile(void) {
    @synchronized (gLogLock) {
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
}

static void LCLog(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void LCLog(NSString *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[LCIsolator] %@", msg);
    ensureLogFile();
    @synchronized (gLogLock) {
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

// Path keychain khusus cid ini (TIDAK pernah auto-copy keychain file container lain).
static NSString *fakeKeychainPath(void) {
    return libPath([NSString stringWithFormat:@"lc_fake_keychain_%@.plist", getContainerID()]);
}

#pragma mark - 1. Device Identifiers (IDFV, IDFA, UIDevice.name, NSProcessInfo.hostName)

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
    NSString *cid = getContainerID();
    NSString *shortID = cid.length > 8 ? [cid substringToIndex:8] : cid;
    return [NSString stringWithFormat:@"iPhone-%@.local", shortID];
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

static NSURL *(*orig_containerURLForGroup)(id, SEL, NSString *);
static NSURL *my_containerURLForGroup(id self, SEL _cmd, NSString *gid) {
    if (!gid.length) return orig_containerURLForGroup(self, _cmd, gid);
    NSString *base = [[NSHomeDirectory() stringByAppendingPathComponent:@"Library/LCAppGroups"]
                      stringByAppendingPathComponent:gid];
    [self createDirectoryAtPath:base withIntermediateDirectories:YES attributes:nil error:nil];
    return [NSURL fileURLWithPath:base isDirectory:YES];
}

#pragma mark - 3. Selective NSUserDefaults (6 domain methods) & CFPreferences*

#if LC_ISOLATE_PREFS
static __thread BOOL tInPrefs = NO;

static BOOL shouldScopeDomain(NSString *name) {
    if (![name isKindOfClass:[NSString class]] || !name.length) return NO;
    if ([name isEqualToString:NSGlobalDomain] ||
        [name isEqualToString:NSArgumentDomain] ||
        [name isEqualToString:NSRegistrationDomain]) return NO;
    if ([name hasPrefix:@"com.apple."] ||
        [name hasPrefix:@"Apple"] ||
        [name hasPrefix:@".GlobalPreferences"]) return NO;
    if ([name hasPrefix:@"lc."]) return NO;
    // Jangan ubah domain bundle ID utama (sudah diisolasi oleh standardUserDefaults LiveContainer).
    NSString *bid = [NSBundle mainBundle].bundleIdentifier;
    if (bid.length && [name isEqualToString:bid]) return NO;
    return YES;
}

static NSString *scopedDomain(NSString *name) {
    if (!shouldScopeDomain(name)) return name;
    return [NSString stringWithFormat:@"lc.%@.%@", getContainerID(), name];
}

static id (*orig_udInitWithSuiteName)(id, SEL, NSString *);
static id my_udInitWithSuiteName(id self, SEL _cmd, NSString *suiteName) {
    if (tInPrefs || tInInternalIO || !shouldScopeDomain(suiteName)) {
        return orig_udInitWithSuiteName(self, _cmd, suiteName);
    }
    tInPrefs = YES;
    NSString *sc = scopedDomain(suiteName);
    id r = orig_udInitWithSuiteName(self, _cmd, sc);
    tInPrefs = NO;
    return r;
}

static void (*orig_udAddSuite)(id, SEL, NSString *);
static void my_udAddSuite(id self, SEL _cmd, NSString *suiteName) {
    if (tInPrefs || tInInternalIO || !shouldScopeDomain(suiteName)) {
        orig_udAddSuite(self, _cmd, suiteName);
        return;
    }
    tInPrefs = YES;
    orig_udAddSuite(self, _cmd, scopedDomain(suiteName));
    tInPrefs = NO;
}

static void (*orig_udRemoveSuite)(id, SEL, NSString *);
static void my_udRemoveSuite(id self, SEL _cmd, NSString *suiteName) {
    if (tInPrefs || tInInternalIO || !shouldScopeDomain(suiteName)) {
        orig_udRemoveSuite(self, _cmd, suiteName);
        return;
    }
    tInPrefs = YES;
    orig_udRemoveSuite(self, _cmd, scopedDomain(suiteName));
    tInPrefs = NO;
}

static NSDictionary *(*orig_udPersistentDomain)(id, SEL, NSString *);
static NSDictionary *my_udPersistentDomain(id self, SEL _cmd, NSString *domainName) {
    if (tInPrefs || tInInternalIO || !shouldScopeDomain(domainName)) {
        return orig_udPersistentDomain(self, _cmd, domainName);
    }
    tInPrefs = YES;
    NSDictionary *r = orig_udPersistentDomain(self, _cmd, scopedDomain(domainName));
    tInPrefs = NO;
    return r;
}

static void (*orig_udSetPersistentDomain)(id, SEL, NSDictionary *, NSString *);
static void my_udSetPersistentDomain(id self, SEL _cmd, NSDictionary *domain, NSString *domainName) {
    if (tInPrefs || tInInternalIO || !shouldScopeDomain(domainName)) {
        orig_udSetPersistentDomain(self, _cmd, domain, domainName);
        return;
    }
    tInPrefs = YES;
    orig_udSetPersistentDomain(self, _cmd, domain, scopedDomain(domainName));
    tInPrefs = NO;
}

static void (*orig_udRemovePersistentDomain)(id, SEL, NSString *);
static void my_udRemovePersistentDomain(id self, SEL _cmd, NSString *domainName) {
    if (tInPrefs || tInInternalIO || !shouldScopeDomain(domainName)) {
        orig_udRemovePersistentDomain(self, _cmd, domainName);
        return;
    }
    tInPrefs = YES;
    orig_udRemovePersistentDomain(self, _cmd, scopedDomain(domainName));
    tInPrefs = NO;
}

// ---- C-API CFPreferences* (dipakai oleh APMUserDefaults di GoPay main binary) ----
static CFPropertyListRef (*orig_CFPreferencesCopyAppValue)(CFStringRef, CFStringRef);
static void (*orig_CFPreferencesSetAppValue)(CFStringRef, CFPropertyListRef, CFStringRef);
static CFArrayRef (*orig_CFPreferencesCopyKeyList)(CFStringRef, CFStringRef, CFStringRef);
static void (*orig_CFPreferencesSetMultiple)(CFDictionaryRef, CFArrayRef, CFStringRef, CFStringRef, CFStringRef);
static Boolean (*orig_CFPreferencesAppSynchronize)(CFStringRef);
static void (*orig_CFPreferencesRemoveSuitePreferencesFromApp)(CFStringRef, CFStringRef);

static NSString *maybeScopeCFAppID(CFStringRef appID) {
    if (!appID ||
        CFEqual(appID, kCFPreferencesCurrentApplication) ||
        CFEqual(appID, kCFPreferencesAnyApplication)) {
        return nil;
    }
    NSString *s = (__bridge NSString *)appID;
    return shouldScopeDomain(s) ? scopedDomain(s) : nil;
}

static CFPropertyListRef my_CFPreferencesCopyAppValue(CFStringRef key, CFStringRef appID) {
    if (tInPrefs || tInInternalIO) return orig_CFPreferencesCopyAppValue(key, appID);
    tInPrefs = YES;
    NSString *sc = maybeScopeCFAppID(appID);
    CFPropertyListRef r = orig_CFPreferencesCopyAppValue(key, sc ? (__bridge CFStringRef)sc : appID);
    tInPrefs = NO;
    return r;
}

static void my_CFPreferencesSetAppValue(CFStringRef key, CFPropertyListRef value, CFStringRef appID) {
    if (tInPrefs || tInInternalIO) { orig_CFPreferencesSetAppValue(key, value, appID); return; }
    tInPrefs = YES;
    NSString *sc = maybeScopeCFAppID(appID);
    orig_CFPreferencesSetAppValue(key, value, sc ? (__bridge CFStringRef)sc : appID);
    tInPrefs = NO;
}

static CFArrayRef my_CFPreferencesCopyKeyList(CFStringRef appID, CFStringRef userName, CFStringRef hostName) {
    if (tInPrefs || tInInternalIO) return orig_CFPreferencesCopyKeyList(appID, userName, hostName);
    tInPrefs = YES;
    NSString *sc = maybeScopeCFAppID(appID);
    CFArrayRef r = orig_CFPreferencesCopyKeyList(sc ? (__bridge CFStringRef)sc : appID, userName, hostName);
    tInPrefs = NO;
    return r;
}

static void my_CFPreferencesSetMultiple(CFDictionaryRef keysToSet, CFArrayRef keysToRemove,
                                        CFStringRef appID, CFStringRef userName, CFStringRef hostName) {
    if (tInPrefs || tInInternalIO) {
        orig_CFPreferencesSetMultiple(keysToSet, keysToRemove, appID, userName, hostName);
        return;
    }
    tInPrefs = YES;
    NSString *sc = maybeScopeCFAppID(appID);
    orig_CFPreferencesSetMultiple(keysToSet, keysToRemove, sc ? (__bridge CFStringRef)sc : appID, userName, hostName);
    tInPrefs = NO;
}

static Boolean my_CFPreferencesAppSynchronize(CFStringRef appID) {
    if (tInPrefs || tInInternalIO) return orig_CFPreferencesAppSynchronize(appID);
    tInPrefs = YES;
    NSString *sc = maybeScopeCFAppID(appID);
    Boolean r = orig_CFPreferencesAppSynchronize(sc ? (__bridge CFStringRef)sc : appID);
    tInPrefs = NO;
    return r;
}

static void my_CFPreferencesRemoveSuitePreferencesFromApp(CFStringRef appID, CFStringRef suiteID) {
    if (tInPrefs || tInInternalIO) {
        orig_CFPreferencesRemoveSuitePreferencesFromApp(appID, suiteID);
        return;
    }
    tInPrefs = YES;
    NSString *scApp = maybeScopeCFAppID(appID);
    NSString *scSuite = maybeScopeCFAppID(suiteID);
    orig_CFPreferencesRemoveSuitePreferencesFromApp(scApp ? (__bridge CFStringRef)scApp : appID,
                                                  scSuite ? (__bridge CFStringRef)scSuite : suiteID);
    tInPrefs = NO;
}
#endif

#pragma mark - 4. Cookies, URLCache, URLCredentialStorage, URLSession, & WebView Isolation

#if LC_ISOLATE_WEB_NET
static __thread BOOL tInNetIso = NO;
static NSObject *gNetLock;
static NSHTTPCookieStorage *gIsoCookieStorage;
static NSString *gIsoCookieCID;
static dispatch_queue_t gCookieSaveQueue;
static BOOL gCookieSaveScheduled = NO;

static NSURLCache *gIsoURLCache;
static NSString *gIsoCacheCID;
static NSURLCredentialStorage *gIsoCredStorage;
static NSString *gIsoCredCID;

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

static void persistIsolatedCookiesNow(void) {
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

static void scheduleCookieSave(void) {
    if (!gCookieSaveQueue) return;
    dispatch_async(gCookieSaveQueue, ^{
        if (gCookieSaveScheduled) return;
        gCookieSaveScheduled = YES;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), gCookieSaveQueue, ^{
            gCookieSaveScheduled = NO;
            persistIsolatedCookiesNow();
        });
    });
}

// Memakai ephemeralSessionConfiguration.HTTPCookieStorage -> instance NSHTTPCookieStorage ASLI
// dengan CFHTTPCookieStorageRef privat (100% public API, kompatibel penuh dengan CFNetwork/NSURLSession/
// NebulaWK PSDXMLHTTPREQUESTMESSAGE/WVWKCookieUtil/flutter_inappwebview_ios), dipersist ke file container.
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
        }
        [[NSNotificationCenter defaultCenter] addObserverForName:NSHTTPCookieManagerCookiesChangedNotification
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

static void (*orig_setSharedURLCache)(id, SEL, NSURLCache *);
static void my_setSharedURLCache(id self, SEL _cmd, NSURLCache *cache) {
    (void)self; (void)_cmd;
    if (cache) {
        @synchronized (gNetLock) {
            gIsoURLCache = cache;
            gIsoCacheCID = [getContainerID() copy];
        }
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

// Isolasi identifier background URLSession agar tidak tabrakan di daemon nsurlsessiond
// (dipakai GoPay, GoogleUtilities com.gul.network.background-upload, GTMSessionFetcher).
static NSURLSessionConfiguration *(*orig_bgSessionConfig)(id, SEL, NSString *);
static NSURLSessionConfiguration *my_bgSessionConfig(id self, SEL _cmd, NSString *identifier) {
    NSString *scoped = identifier;
    if (identifier.length && ![identifier hasPrefix:@"lc."]) {
        scoped = [NSString stringWithFormat:@"lc.%@.%@", getContainerID(), identifier];
    }
    NSURLSessionConfiguration *cfg = orig_bgSessionConfig(self, _cmd, scoped);
    if (!tInNetIso && cfg) {
        tInNetIso = YES;
        cfg.HTTPCookieStorage = isolatedCookieStorage();
        cfg.URLCache = isolatedURLCache();
        cfg.URLCredentialStorage = isolatedCredentialStorage();
        tInNetIso = NO;
    }
    return cfg;
}

// ---- WKWebsiteDataStore + WKWebViewConfiguration + WKWebView + WKProcessPool ----
static WKWebsiteDataStore *gIsoWKStore;
static NSString *gIsoWKCID;
static WKProcessPool *gIsoWKPool;
static __thread BOOL tInWKInit = NO;

static WKWebsiteDataStore *isolatedStore(void) {
    NSString *cid = getContainerID();
    if (gIsoWKStore && [gIsoWKCID isEqualToString:cid]) return gIsoWKStore;
    void (^make)(void) = ^{
        if (gIsoWKStore && [gIsoWKCID isEqualToString:cid]) return;
        if (@available(iOS 17.0, *)) {
            gIsoWKStore = [WKWebsiteDataStore dataStoreForIdentifier:uuidFromString(cid)];
        } else {
#if LC_WEBVIEW_IOS16_NONPERSIST
            gIsoWKStore = [WKWebsiteDataStore nonPersistentDataStore];
#endif
        }
        gIsoWKCID = [cid copy];
        LCLog(@"WKWebsiteDataStore: %@", gIsoWKStore ? @"ISOLATED" : @"TIDAK terisolasi (iOS <17)");
    };
    if ([NSThread isMainThread]) make();
    else dispatch_sync(dispatch_get_main_queue(), make);
    return gIsoWKStore;
}

static WKProcessPool *isolatedProcessPool(void) {
    static dispatch_once_t t;
    dispatch_once(&t, ^{
        gIsoWKPool = [[WKProcessPool alloc] init];
    });
    return gIsoWKPool;
}

static WKWebsiteDataStore *(*orig_wkDefaultDataStore)(id, SEL);
static WKWebsiteDataStore *my_wkDefaultDataStore(id self, SEL _cmd) {
    if (tInWKInit) return orig_wkDefaultDataStore(self, _cmd);
    tInWKInit = YES;
    WKWebsiteDataStore *iso = isolatedStore();
    tInWKInit = NO;
    return iso ?: orig_wkDefaultDataStore(self, _cmd);
}

// CRITICAL FIX: Pasang store & processPool container sejak WKWebViewConfiguration lahir!
// Mencegah cookie yang diset ke cfg.websiteDataStore.httpCookieStore SEBELUM initWithFrame:configuration:
// bocor ke store host lalu hilang saat store diganti.
static id (*orig_wkCfgInit)(id, SEL);
static id my_wkCfgInit(id self, SEL _cmd) {
    WKWebViewConfiguration *cfg = orig_wkCfgInit(self, _cmd);
    if (cfg && !tInWKInit) {
        tInWKInit = YES;
#if LC_FORCE_WEBVIEW_STORE
        WKWebsiteDataStore *iso = isolatedStore();
        if (iso) cfg.websiteDataStore = iso;
#endif
        cfg.processPool = isolatedProcessPool();
        tInWKInit = NO;
    }
    return cfg;
}

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
        if (iso) configuration.websiteDataStore = iso;
        configuration.processPool = isolatedProcessPool();
        state = iso ? @"nil-cfg -> DIBUAT store container" : @"nil-cfg (iOS <17)";
#else
        state = @"nil-cfg (dibiarkan)";
#endif
    } else {
        WKWebsiteDataStore *cur = configuration.websiteDataStore;
        if (!cur.isPersistent) {
            state = @"non-persisten (dibiarkan)";
        } else if (iso && cur == iso) {
            state = @"sudah store container";
        } else {
#if LC_FORCE_WEBVIEW_STORE
            if (iso) {
                configuration.websiteDataStore = iso;
                state = @"DIPAKSA ke store container";
            } else {
                state = @"persisten, tidak bisa dipaksa (iOS <17)";
            }
#else
            state = @"persisten, store bersama (LC_FORCE_WEBVIEW_STORE=0)";
#endif
        }
        if (!configuration.processPool) configuration.processPool = isolatedProcessPool();
    }
    static int n = 0;
    if (n++ < 40) LCLog(@"WKWebView init class=%@ store=%@", NSStringFromClass([self class]), state);
    return orig_wkInitFrameCfg(self, _cmd, frame, configuration);
}

static id (*orig_wkInitCoder)(id, SEL, NSCoder *);
static id my_wkInitCoder(id self, SEL _cmd, NSCoder *coder) {
    WKWebView *wv = orig_wkInitCoder(self, _cmd, coder);
    if (wv) {
        LCLog(@"WKWebView initWithCoder class=%@ persistent=%d",
              NSStringFromClass([wv class]), (int)wv.configuration.websiteDataStore.isPersistent);
    }
    return wv;
}
#endif

#pragma mark - 5. Browser / OAuth Isolation & Trace (ASWebAuthenticationSession, SFSafariViewController)

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

static id (*orig_sfInit)(id, SEL, NSURL *, id);
static id my_sfInit(id self, SEL _cmd, NSURL *url, id cfg) {
#if LC_TRACE_WEB
    LCLog(@"SFSafariViewController %@://%@", url.scheme ?: @"-", url.host ?: @"-");
#endif
    return orig_sfInit(self, _cmd, url, cfg);
}

#if LC_TRACE_WEB
static WKNavigation *(*orig_wkLoadRequest)(id, SEL, NSURLRequest *);
static WKNavigation *my_wkLoadRequest(id self, SEL _cmd, NSURLRequest *req) {
    LCLog(@"WKWebView(%@) loadRequest %@://%@%@", NSStringFromClass([self class]),
          req.URL.scheme ?: @"-", req.URL.host ?: @"-", req.URL.path ?: @"");
    return orig_wkLoadRequest(self, _cmd, req);
}

static void (*orig_wkSetCookie)(id, SEL, NSHTTPCookie *, void (^)(void));
static void my_wkSetCookie(id self, SEL _cmd, NSHTTPCookie *cookie, void (^handler)(void)) {
    LCLog(@"WKHTTPCookieStore setCookie name=%@ domain=%@", cookie.name, cookie.domain);
    orig_wkSetCookie(self, _cmd, cookie, handler);
}

static void (*orig_wkAddMsgHandler)(id, SEL, id<WKScriptMessageHandler>, NSString *);
static void my_wkAddMsgHandler(id self, SEL _cmd, id<WKScriptMessageHandler> handler, NSString *name) {
    LCLog(@"WK JS message handler: %@", name);
    orig_wkAddMsgHandler(self, _cmd, handler, name);
}

static void (*orig_appOpenURL)(id, SEL, NSURL *, NSDictionary *, void (^)(BOOL));
static void my_appOpenURL(id self, SEL _cmd, NSURL *url, NSDictionary *options, void (^handler)(BOOL)) {
    LCLog(@"UIApplication openURL %@://%@", url.scheme ?: @"-", url.host ?: @"-");
    orig_appOpenURL(self, _cmd, url, options, handler);
}
#endif

static void installBrowserHooksIfLoaded(void) {
    Class asCls = NSClassFromString(@"ASWebAuthenticationSession");
    if (asCls) {
        hookInstanceMethod(asCls,
                           NSSelectorFromString(@"initWithURL:callbackURLScheme:completionHandler:"),
                           (IMP)my_asInit, (IMP *)&orig_asInit);
    }
#if LC_TRACE_WEB
    Class sfCls = NSClassFromString(@"SFSafariViewController");
    if (sfCls) {
        hookInstanceMethod(sfCls,
                           NSSelectorFromString(@"initWithURL:configuration:"),
                           (IMP)my_sfInit, (IMP *)&orig_sfInit);
    }
#endif
}

#pragma mark - 6. UIPasteboard Isolation (class-cluster safe: _UIConcretePasteboard + named pasteboards)

#if LC_PASTEBOARD_MODE > 0
static NSObject *gPBLock;
static NSMutableArray<NSDictionary<NSString *, id> *> *gPBItems;
static NSInteger gPBChangeCount = 0;

static BOOL isGeneralPB(UIPasteboard *pb) {
    if (!pb) return NO;
    return [pb.name isEqualToString:UIPasteboardNameGeneral];
}

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
#endif
}

static NSArray<NSString *> *(*orig_pbStrings)(id, SEL);
static NSArray<NSString *> *my_pbStrings(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbStrings(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
    return @[];
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
#endif
}

static BOOL (*orig_pbHasStrings)(id, SEL);
static BOOL my_pbHasStrings(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbHasStrings(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
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
#endif
}

static NSArray<NSURL *> *(*orig_pbURLs)(id, SEL);
static NSArray<NSURL *> *my_pbURLs(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbURLs(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
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
#endif
}

static BOOL (*orig_pbHasURLs)(id, SEL);
static BOOL my_pbHasURLs(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbHasURLs(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
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
#endif
}

static NSArray<UIImage *> *(*orig_pbImages)(id, SEL);
static NSArray<UIImage *> *my_pbImages(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbImages(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
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
#endif
}

static BOOL (*orig_pbHasImages)(id, SEL);
static BOOL my_pbHasImages(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbHasImages(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
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
#endif
}

static void (*orig_pbSetItemsOpts)(id, SEL, NSArray<NSDictionary<NSString *, id> *> *, NSDictionary *);
static void my_pbSetItemsOpts(id self, SEL _cmd, NSArray<NSDictionary<NSString *, id> *> *items, NSDictionary *opts) {
    // social_media_share memakai setItems:options: untuk kirim sticker ke Instagram/FB ->
    // izinkan jika target adalah sticker eksternal Instagram/FB, isolasi selain itu.
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
    my_pbSetItems(self, _cmd, items);
}

static void (*orig_pbAddItems)(id, SEL, NSArray<NSDictionary<NSString *, id> *> *);
static void my_pbAddItems(id self, SEL _cmd, NSArray<NSDictionary<NSString *, id> *> *items) {
    if (!isGeneralPB(self)) { orig_pbAddItems(self, _cmd, items); return; }
#if LC_PASTEBOARD_MODE == 1
    @synchronized (gPBLock) {
        if ([items isKindOfClass:[NSArray class]]) [gPBItems addObjectsFromArray:items];
        gPBChangeCount++;
    }
#endif
}

static NSArray<NSString *> *(*orig_pbTypes)(id, SEL);
static NSArray<NSString *> *my_pbTypes(id self, SEL _cmd) {
    if (!isGeneralPB(self)) return orig_pbTypes(self, _cmd);
#if LC_PASTEBOARD_MODE == 2
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
#endif
}

static void (*orig_pbSetDataForType)(id, SEL, NSData *, NSString *);
static void my_pbSetDataForType(id self, SEL _cmd, NSData *data, NSString *type) {
    if (!isGeneralPB(self)) { orig_pbSetDataForType(self, _cmd, data, type); return; }
    my_pbSetValueForType(self, _cmd, data, type);
}

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

#pragma mark - 7. UNUserNotificationCenter Isolation (runtime lookup, tanpa link UserNotifications)

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

static void installNotificationHooksIfLoaded(void) {
    Class un = NSClassFromString(@"UNUserNotificationCenter");
    if (!un) return;
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
}
#endif

#pragma mark - 8. Hardened Keychain Isolation (Passwords + kSecClassKey + Cert/Identity + SecKeyGeneratePair)

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

static NSDictionary *scopeKeyDict(NSDictionary *d, BOOL forceTag) {
    if (!d) return nil;
    NSMutableDictionary *m = [d mutableCopy];
    stripForeignAccessGroup(m);
    id tag = m[(__bridge id)kSecAttrApplicationTag];
    if (tag) {
        m[(__bridge id)kSecAttrApplicationTag] = scopedTag(tag);
    } else if (forceTag) {
        m[(__bridge id)kSecAttrApplicationTag] = tagPrefixData();
    }
    if ([m[(__bridge id)kSecAttrLabel] isKindOfClass:[NSString class]]) {
        m[(__bridge id)kSecAttrLabel] = scopedLabel(m[(__bridge id)kSecAttrLabel]);
    }
    return m;
}

static NSDictionary *scopeKeyParams(NSDictionary *p, BOOL forceTag) {
    if (!p) return nil;
    BOOL hasSubDict = NO;
    for (id sub in @[(__bridge id)kSecPrivateKeyAttrs, (__bridge id)kSecPublicKeyAttrs]) {
        if ([p[sub] isKindOfClass:[NSDictionary class]]) hasSubDict = YES;
    }
    NSMutableDictionary *m = [scopeKeyDict(p, forceTag && !hasSubDict) mutableCopy];
    for (id sub in @[(__bridge id)kSecPrivateKeyAttrs, (__bridge id)kSecPublicKeyAttrs]) {
        NSDictionary *sd = m[sub];
        if ([sd isKindOfClass:[NSDictionary class]]) {
            m[sub] = scopeKeyDict(sd, forceTag);
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

// Aman untuk query kSecClassKey / Cert / Identity TANPA tag/label:
// saring ketat hanya item milik container ini supaya tidak pernah membaca/menghapus kunci container lain!
static OSStatus filteredRealCopyMatching(NSDictionary *q, CFTypeRef *result, BOOL byLabel) {
    NSMutableDictionary *iq = [byLabel ? scopeCertDict(q, NO) : scopeKeyDict(q, NO) mutableCopy];
    iq[(__bridge id)kSecReturnAttributes] = @YES;
    iq[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;

    CFTypeRef raw = NULL;
    OSStatus st = orig_SecItemCopyMatching((__bridge CFDictionaryRef)iq, &raw);
    if (st != errSecSuccess || !raw) {
        if (raw) CFRelease(raw);
        return st;
    }
    id obj = CFBridgingRelease(raw);
    NSArray *list = [obj isKindOfClass:[NSArray class]] ? obj : ([obj isKindOfClass:[NSDictionary class]] ? @[obj] : @[]);
    NSMutableArray *mine = [NSMutableArray array];
    for (id e in list) {
        if ([e isKindOfClass:[NSDictionary class]] && realItemBelongsToContainer(e, byLabel)) {
            [mine addObject:e];
        }
    }
    if (!mine.count) return errSecItemNotFound;

    id lim = q[(__bridge id)kSecMatchLimit];
    BOOL wantMany = [lim isEqual:(__bridge id)kSecMatchLimitAll] ||
                    ([lim isKindOfClass:[NSNumber class]] && [lim integerValue] > 1);
    if (result) {
        if (wantMany) {
            NSInteger cap = [lim isKindOfClass:[NSNumber class]] ? [lim integerValue] : (NSInteger)mine.count;
            NSMutableArray *out = [NSMutableArray array];
            for (NSInteger i = 0; i < (NSInteger)mine.count && i < cap; i++) {
                id f = formatRealKeyItem(mine[i], q);
                if (f) [out addObject:f];
            }
            *result = out.count ? CFRetain((__bridge CFTypeRef)out) : NULL;
        } else {
            id f = formatRealKeyItem(mine[0], q);
            *result = f ? CFRetain((__bridge CFTypeRef)f) : NULL;
        }
    }
    return errSecSuccess;
}

static OSStatus filteredRealDelete(NSDictionary *q, BOOL byLabel) {
    NSMutableDictionary *iq = [byLabel ? scopeCertDict(q, NO) : scopeKeyDict(q, NO) mutableCopy];
    [iq removeObjectForKey:(__bridge id)kSecReturnData];
    [iq removeObjectForKey:(__bridge id)kSecReturnRef];
    iq[(__bridge id)kSecReturnAttributes] = @YES;
    iq[(__bridge id)kSecReturnPersistentRef] = @YES;
    iq[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;

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
    iq[(__bridge id)kSecReturnAttributes] = @YES;
    iq[(__bridge id)kSecReturnPersistentRef] = @YES;
    iq[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;

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

static NSString *strOrEmpty(id v) {
    if (!v) return @"";
    if ([v isKindOfClass:[NSData class]]) {
        return [(NSData *)v base64EncodedStringWithOptions:0];
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

    // kSecAttrAccessible: cocokkan hanya jika item punya nilai tersimpan (kompatibel legacy v9)
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

static BOOL persistentRefExistsInFakeKC(NSDictionary *q) {
    NSData *pref = q[(__bridge id)kSecValuePersistentRef];
    if (![pref isKindOfClass:[NSData class]] || !pref.length) return NO;
    NSString *key = [[NSString alloc] initWithData:pref encoding:NSUTF8StringEncoding];
    if (!key.length) return NO;
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

    // 1. Cek persistentRef di fake keychain DULU (query persistentRef sering tanpa kSecClass!)
    BOOL isFakePRef = persistentRefExistsInFakeKC(q);
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

    BOOL isFakePRef = persistentRefExistsInFakeKC(q);
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

    BOOL isFakePRef = persistentRefExistsInFakeKC(q);
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

#pragma mark - 9. Diagnostik Key / Biometrik

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

#if LC_TRACE_AUTH
static BOOL (*orig_laCan)(id, SEL, NSInteger, NSError **);
static BOOL my_laCan(id self, SEL _cmd, NSInteger policy, NSError **err) {
    NSError *local = nil;
    BOOL r = orig_laCan(self, _cmd, policy, err ? err : &local);
    NSError *e = r ? nil : (err ? *err : local);
    LCLog(@"LAContext canEvaluatePolicy policy=%ld -> %@ errcode=%ld",
          (long)policy, r ? @"YA" : @"TIDAK", (long)e.code);
    return r;
}

static void (*orig_laEval)(id, SEL, NSInteger, NSString *, void (^)(BOOL, NSError *));
static void my_laEval(id self, SEL _cmd, NSInteger policy, NSString *reason, void (^reply)(BOOL, NSError *)) {
    LCLog(@"LAContext evaluatePolicy policy=%ld dimulai", (long)policy);
    orig_laEval(self, _cmd, policy, reason, ^(BOOL ok, NSError *e) {
        LCLog(@"LAContext evaluatePolicy -> %@ errcode=%ld", ok ? @"BERHASIL" : @"GAGAL", (long)e.code);
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

static void logPermissionStatusIfLoaded(void) {
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
}
#endif

#pragma mark - Deferred Hooks (setelah UIApplication siap, tanpa force-dlopen di constructor)

static void installDeferredHooks(void) {
#if LC_ISOLATE_WEB_NET
    // Pre-warm di main thread setelah UIApplication siap (mencegah deadlock dispatch_sync dari background thread)
    (void)isolatedStore();
    (void)isolatedProcessPool();
#endif
#if LC_ISOLATE_DEVICE_IDS
    installAdSupportHookIfLoaded();
#endif
#if LC_PASTEBOARD_MODE > 0
    // Pastikan subclass class cluster (_UIConcretePasteboard) ikut ter-hook
    installPasteboardHooksOnClass([UIPasteboard generalPasteboard].class);
#endif
#if LC_ISOLATE_NOTIFICATIONS
    installNotificationHooksIfLoaded();
#endif
    installBrowserHooksIfLoaded();
#if LC_TRACE_AUTH
    installAuthTraceIfLoaded();
    logPermissionStatusIfLoaded();
#endif
}

#pragma mark - Init

__attribute__((constructor))
static void lc_init(void) {
    gLogLock = [NSObject new];
    gCIDLock = [NSObject new];
    gIDFVLock = [NSObject new];
    gLock = [NSObject new];
#if LC_ISOLATE_WEB_NET
    gNetLock = [NSObject new];
#endif
#if LC_PASTEBOARD_MODE > 0
    gPBLock = [NSObject new];
    gPBItems = [NSMutableArray array];
#endif

    LCLog(@"=== init v10 home=%@", NSHomeDirectory());

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
    hookClassMethod([NSURLSessionConfiguration class], @selector(defaultSessionConfiguration),
                    (IMP)my_defaultSessionConfig, (IMP *)&orig_defaultSessionConfig);
    hookClassMethod([NSURLSessionConfiguration class], @selector(backgroundSessionConfigurationWithIdentifier:),
                    (IMP)my_bgSessionConfig, (IMP *)&orig_bgSessionConfig);

    hookClassMethod([WKWebsiteDataStore class], @selector(defaultDataStore),
                    (IMP)my_wkDefaultDataStore, (IMP *)&orig_wkDefaultDataStore);
    hookInstanceMethod([WKWebViewConfiguration class], @selector(init),
                       (IMP)my_wkCfgInit, (IMP *)&orig_wkCfgInit);
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

#if LC_ISOLATE_NOTIFICATIONS
    installNotificationHooksIfLoaded();
#endif
    installBrowserHooksIfLoaded();
#endif

#if LC_TRACE_WEB
    hookInstanceMethod([WKWebView class], @selector(loadRequest:),
                       (IMP)my_wkLoadRequest, (IMP *)&orig_wkLoadRequest);
    hookInstanceMethod([WKHTTPCookieStore class], @selector(setCookie:completionHandler:),
                       (IMP)my_wkSetCookie, (IMP *)&orig_wkSetCookie);
    hookInstanceMethod([WKUserContentController class], @selector(addScriptMessageHandler:name:),
                       (IMP)my_wkAddMsgHandler, (IMP *)&orig_wkAddMsgHandler);
    hookInstanceMethod([UIApplication class], @selector(openURL:options:completionHandler:),
                       (IMP)my_appOpenURL, (IMP *)&orig_appOpenURL);
#endif

#if LC_TRACE_AUTH
    installAuthTraceIfLoaded();
#endif

    // Hook C symbols via fishhook (hanya sekali, mencakup semua image yang sudah & akan dimuat)
    struct rebinding rebs[20];
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
    if (count > 0) {
        int rc = rebind_symbols(rebs, count);
        LCLog(@"rebind_symbols count=%zu rc=%d", count, rc);
    }

    // Hook framework opsional & simpan cookie saat app masuk background / selesai launch.
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc addObserverForName:UIApplicationWillFinishLaunchingNotification
                    object:nil
                     queue:[NSOperationQueue mainQueue]
                usingBlock:^(NSNotification *n) {
        (void)n;
        LCLog(@"WillFinishLaunching container=%@ home=%@", getContainerID(), NSHomeDirectory());
        installDeferredHooks();
    }];
    [nc addObserverForName:UIApplicationDidFinishLaunchingNotification
                    object:nil
                     queue:[NSOperationQueue mainQueue]
                usingBlock:^(NSNotification *n) {
        (void)n;
        installDeferredHooks();
    }];
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

    LCLog(@"=== init v10 selesai");
}
