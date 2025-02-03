#!/bin/bash
AFL_LLVM_INSTRIM_LOOPHEAD=1 AFL_LLVM_CMPLOG=1 afl-clang-fast -o target_binary target.c
