
#cross-compile

#cflag for nvram
CROSSCFLAGS :=

# PROGRAM   := a.out    # the executable name
PROGRAM   := auth-box

# SRCDIRS   := .        # current directory
SRCDIRS   := .

# The source file types (headers excluded).
SRCEXTS   := .c .cpp

# CPPFLAGS  := -Wall -Werror # show all warnings and take them as errors
CPPFLAGS  :=
CC	= msdk-linux-gcc
CXX 	= msdk-linux-gcc
#-pthread define _REENTRANT

CXXFLAGS  := -Wall -Os
CXXFLAGS  +=

CFLAGS	  := -Wall
# The library and the link options ( C and C++ common).

## Stable Section: usually no need to be changed. But you can add more.
##=============================================================================
SHELL   = /bin/sh
SOURCES = $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))


OBJS    = $(foreach x,$(SRCEXTS), \
      		$(patsubst %$(x),%.o,$(filter %$(x),$(SOURCES))))

DEPS    = $(patsubst %.o,%.d,$(OBJS))

.PHONY : ftp nfs all objs clean cleanall rebuild strip

compile : $(PROGRAM)

# Rules for producing the objects.
#---------------------------------------------------
objs : $(OBJS)

%.o : %.c
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $<

%.o : %.C
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $<

%.o : %.cc
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $<

%.o : %.cpp
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $<

%.o : %.CPP
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $<

%.o : %.c++
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $<

%.o : %.cp
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $<

%.o : %.cxx
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $<

# Rules for producing the executable.
#----------------------------------------------
$(PROGRAM) : $(OBJS)
ifeq ($(strip $(SRCEXTS)), .c)  # C file
	$(CC)  $(LDFLAGS) -o $(PROGRAM) $(OBJS) 
else                            # C++ file
	$(CXX) $(LDFLAGS) -o $(PROGRAM) $(OBJS) 
endif
	
-include $(DEPS)


rebuild: clean all

strip: all
	$(CROSS)strip $(PROGRAM)

nfs: all strip
	cp $(PROGRAM) /root/nfs -f
ftp: all strip
	cp $(PROGRAM) ~/public/up -f
clean :
	$(RM) *.o *.d
	$(RM) $(PROGRAM)

distclean: clean
	$(RM) $(PROGRAM) $(PROGRAM).exe

### End of the Makefile ##  Suggestions are welcome  ## All rights reserved ###
###############################################################################
