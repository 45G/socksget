TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.c

LIBS += -L$$_PRO_FILE_PWD_/libsocks6msg/ -lsocks6msg
