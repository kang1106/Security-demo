BIN_NAME = crypto_service

ROOT = ../../../..

CXX = g++
CC = gcc

#INCLUDES = $(addprefix -I, $(ROOT)/include/openssl)
INCLUDES = -I$(ROOT)/include/vsomeip -I$(ROOT)/include

DEPFILE = Make.depend
DEPDIR = .depend
MKDIR = mkdir -p

LIB_DIRS = -L${ROOT}/lib/glog -L${ROOT}/lib/openssl -L${ROOT}/lib/vsomeip
LIBS = \
	-lglog \
	-lssl \
	-lcrypto \
	-lpthread \
	-ldl \
	-lvsomeip3

# the sources (note: using :=, not = )    
#CPPS := $(wildcard $(BASE)/CycurV2XClient/Client/*.cpp)
CPPS := crypto_service_main.cpp

OBJS := $(patsubst %.cpp,%.o,$(notdir $(CPPS)))

CSRC := 
OBJC := $(patsubst %.c,%.o,$(notdir $(CSRC))) 

%.o: 
	$(eval SFX=$(suffix $< ))
	@echo Building $@ from $(SFX) file  $< 
	@if [ "$(SFX)" = ".c" ]; \
	then \
		echo $(CC) $(CFLAGS) $(INCLUDES)  -o $@ -c $< ;\
		$(CC) $(CFLAGS) $(INCLUDES) $(LIB_DIRS) $(LIBS) -o $@ -c $< ;\
	else \
		echo $(CXX) $(CXXFLAGS) $(INCLUDES)  -o $@ -c $< ;\
		$(CXX) $(CXXFLAGS) $(INCLUDES) $(LIB_DIRS) $(LIBS) -o $@ -c $< ;\
	fi

$(BIN_NAME): $(OBJS)
	@echo "Compiling $(BIN_NAME)..."
	$(CXX) $(OBJS) $(INCLUDES) $(CXXFLAGS) $(LIB_DIRS) $(LIBS) -o $@
	@echo "Done!"

mostclean : clean
	@rm -rf .depend

clean:
	@echo Cleaning local directory : `pwd`
	@rm -rf $(OBJS) $(OBJC) $(OBJMAIN) lib$(LIB_NAME).a $(EXE) $(DEPDIR) $(EXE).map $(BIN_NAME)

depend: $(DEPDIR)/$(DEPFILE)
	@touch $(DEPDIR)/$(DEPFILE)

$(DEPDIR)/$(DEPFILE):
	@echo Makefile - building dependencies in: $@
	@$(MKDIR) $(DEPDIR)
	@$(CXX) -E -MM $(CXXFLAGS) $(INCLUDES)  $(CPPS) $(CSRC) >> $@

ifeq (,$(findstring clean,$(MAKECMDGOALS)))
-include $(DEPDIR)/$(DEPFILE)
endif
