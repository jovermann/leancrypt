# Copyright (c) 2024 Johannes Overmann
#
# Distributed under the Boost Software License, Version 1.0.
# (See accompanying file LICENSE or copy at https://www.boost.org/LICENSE_1_0.txt)

# For GCC:
#CXXFLAGS ?= -Wall -Wextra -O3
# For clang:
CXXFLAGS ?= -O3 -Weverything -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-padded -Wno-shorten-64-to-32 -Wno-missing-prototypes -Wno-sign-conversion -Wno-implicit-int-conversion -Wno-poison-system-directories -fcomment-block-commands=n -Wno-string-conversion
CPPFLAGS ?= -pedantic -Iinclude -I.
CXXSTD ?= -std=c++20 # Min c++20 for rotl/rotr

BUILDDIR=build
SOURCES = $(wildcard src/*.cpp)
OBJECTS = $(SOURCES:%.cpp=$(BUILDDIR)/%.o)
DEPENDS := $(SOURCES:%.cpp=$(BUILDDIR)/%.d)

TARGET = bench
default: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $^ -o $@

build/%.o: %.cpp build/%.d
	$(CXX) $(CXXSTD) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

build/%.d: %.cpp Makefile
	@mkdir -p $(@D)
	$(CXX) $(CXXSTD) $(CPPFLAGS) -MM -MQ $@ $< -o $@

clean:
	rm -rf build $(TARGET) unit_test
	find . -name '*~' -delete

.PHONY: clean default

ifeq ($(findstring $(MAKECMDGOALS),clean),)
-include $(DEPENDS)
endif
