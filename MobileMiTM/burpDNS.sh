#!/bin/bash
PRG="$0"
while [ -h "$PRG" ] ; do
  ls=`ls -ld "$PRG"`
  link=`expr "$ls" : '.*-> \(.*\)$'`
  if expr "$link" : '/.*' > /dev/null; then
    PRG="$link"
  else
    PRG=`dirname "$PRG"`/"$link"
  fi
done
ROOT=`dirname "$PRG"`

java  -Djava.net.preferIPv4Stack=true -Djava.library.path=$ROOT -classpath $ROOT/.:$ROOT/suite.jar:$ROOT/MiTMExtender.jar burp.StartBurp
