pkglib_LTLIBRARIES =
lib_LTLIBRARIES =
dist_man7_MANS =
dist_man1_MANS =

AM_CPPFLAGS = @OVIS_INCLUDE_ABS@
AM_LDFLAGS = @OVIS_LIB_ABS@
COMMON_LIBADD = -lsampler_base -lldms -lovis_util -lcoll

if ENABLE_DAOS_SAMPLER
libdaos_la_SOURCES = daos.h daos.c \
		     rank_target.h rank_target.c \
		     pool_target.h pool_target.c
libdaos_la_LIBADD = $(COMMON_LIBADD) -lgurt
pkglib_LTLIBRARIES += libdaos.la
dist_man7_MANS += Plugin_daos.man
endif
