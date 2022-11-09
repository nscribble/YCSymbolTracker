//
//  YCSymbolTracker.m
//  YCSymbolTracker
//
//  Created by ycpeng on 2020/6/10.
//

#import "YCSymbolTracker.h"

#import <stdint.h>
#import <stdio.h>
#import <sanitizer/coverage_interface.h>
#import <libkern/OSAtomic.h>
#import <dlfcn.h>
#import <os/lock.h>

static OSQueueHead symbolList = OS_ATOMIC_QUEUE_INIT;
static BOOL finished;
static NSMutableDictionary *mappings;
static os_unfair_lock lock;

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    static uint64_t N;  // Counter for the guards.
    if (start == stop || *start) return;  // Initialize only once.
    
    for (uint32_t *x = start; x < stop; x++) {
        *x = (uint32_t)++N;  // Guards should start from 1.
    }
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        mappings = [NSMutableDictionary dictionaryWithCapacity:1000];
        lock = OS_UNFAIR_LOCK_INIT;
    });
}

typedef struct {
    void *pc;
    void *next;
} SymbolNode;

// https://clang.llvm.org/docs/SanitizerCoverage.html

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
//    if (!*guard) return;  // Duplicate the guard check.
    if (finished) {
        *guard = 0;
        return;
    }
    
    void *PC = __builtin_return_address(0);
    
    int64_t pcw = (int64_t)PC;
    int32_t pch = (pcw & 0xFFFFFFFF00000000) >> 32;
    
    os_unfair_lock_lock(&lock);
    NSMutableDictionary *sub = [mappings objectForKey:@(pch)];
    if (sub && sub[@(pcw)]) {
        os_unfair_lock_unlock(&lock);
        return;
    }
    
    if (!sub) {
        sub = [NSMutableDictionary dictionaryWithCapacity:10000];
        mappings[@(pch)] = sub;
    }
    sub[@(pcw)] = @1;
    os_unfair_lock_unlock(&lock);
    
    SymbolNode * node = malloc(sizeof(SymbolNode));
    *node = (SymbolNode){PC, NULL};
    
    OSAtomicEnqueue(&symbolList, node, offsetof(SymbolNode, next));
}

@implementation YCSymbolTracker

+ (BOOL)exportSymbolsWithFilePath:(nonnull NSString *)filePath
{
    finished = YES;
    
    NSMutableArray <NSString *>* symbolNames = [NSMutableArray array];
    while (YES) {
        SymbolNode *node = OSAtomicDequeue(&symbolList, offsetof(SymbolNode, next));
        if (node == NULL) {
            break;
        }
        Dl_info info;
        dladdr(node->pc, &info);
        
        NSString * name = @(info.dli_sname);
        BOOL isObjc = [name hasPrefix:@"+["] || [name hasPrefix:@"-["]; // Objective-C method do nothing
        NSString * symbolName = isObjc? name : [@"_" stringByAppendingString:name]; // c function with "_"
        [symbolNames addObject:symbolName];
    }
    
    NSEnumerator * emt = [symbolNames reverseObjectEnumerator];
    NSMutableArray<NSString*>* funcs = [NSMutableArray arrayWithCapacity:symbolNames.count];
    NSString * name;
    while (name = [emt nextObject]) {
        if (![funcs containsObject:name]) {
            [funcs addObject:name];
        }
    }
    // remove current method symbol (not necessary when launch)
    [funcs removeObject:[NSString stringWithFormat:@"%s", __FUNCTION__]];
    
    NSString *funcStr = [funcs componentsJoinedByString:@"\n"];
    NSData * fileContents = [funcStr dataUsingEncoding:NSUTF8StringEncoding];
    if ([[NSFileManager defaultManager] fileExistsAtPath:filePath]) {
        [[NSFileManager defaultManager] removeItemAtPath:filePath error:nil];
    }
    return [[NSFileManager defaultManager] createFileAtPath:filePath contents:fileContents attributes:nil];
}

@end
