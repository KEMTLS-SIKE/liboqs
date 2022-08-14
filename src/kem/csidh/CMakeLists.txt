# SPDX-License-Identifier: MIT

set (CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED TRUE)
set(CMAKE_C_EXTENSIONS OFF)

set(SRCS external/rng.c external/mont.c external/csidh.c)

set(SRCS ${SRCS} external/p512/uint.s)
set(SRCS ${SRCS} external/p512/fp.s external/p512/inv/fpadd511.s external/p512/inv/fpcneg511.s external/p512/inv/fpinv511.c external/p512/inv/fpmul2x2_511_half.c external/p512/inv/fpmul511.s external/p512/inv/jump64divsteps2_s511.s external/p512/inv/muls64xs64.s external/p512/inv/muls128xs128.s external/p512/inv/muls256xs256.s external/p512/inv/norm500_511.s)
set(SRCS ${SRCS} external/p512/constants.c)

set(SRCS ${SRCS} kem_csidh.c)

add_library(csidh OBJECT ${SRCS})