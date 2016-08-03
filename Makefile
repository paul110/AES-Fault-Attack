SOURCES_C    = $(wildcard *.c   )
TARGETS_C    = $(patsubst %.c,    %,       ${SOURCES_C}   )
SOURCES_JAVA = $(wildcard *.java)
TARGETS_JAVA = $(patsubst %.java, %.class, ${SOURCES_JAVA})

${TARGETS_C}    : %       : %.c %.h
	@gcc -fopenmp -Wall -std=gnu99 -O3 -o ${@} $(filter %.c, ${^}) -lgmp -lcrypto

${TARGETS_JAVA} : %.class : %.java
	@javac ${^}

.DEFAULT_GOAL = all

all   :             ${TARGETS_C} ${TARGETS_JAVA}

clean :
	@rm -f core ${TARGETS_C} ${TARGETS_JAVA} *.pyo *.pyc
