#!/bin/sh -ex

cd $HOME/git/bpmc/bpm-console-gitsvn
mvn install -DskipTests # produces $HOME/.m2/repository/org/jboss/bpm/gwt-console-server/2.1/gwt-console-server-2.1-jbpm.war
cd $HOME/git/droolsjbpm/jbpm/jbpm-gwt; mvn -DskipTests install # produces $HOME/.m2/repository/org/jbpm/jbpm-gwt-console/5.1.2-SNAPSHOT/jbpm-gwt-console-5.1.2-SNAPSHOT.war
cd $HOME/git/droolsjbpm/jbpm/jbpm-distribution; mvn -DskipTests install # produces target/jbpm-5.1.2-SNAPSHOT-gwt-console.zip
cp target/jbpm-5.1.2-SNAPSHOT-gwt-console.zip $HOME/git/droolsjbpm/jbpm/jbpm-installer/lib
cd $HOME/git/droolsjbpm/jbpm/jbpm-installer; ant install.jBPM-gwt-console.into.jboss
