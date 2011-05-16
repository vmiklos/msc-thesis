#!/bin/sh -ex

version=$(git describe --tags)
unzip LPSP.uno.pkg description.xml
sed -i '5i<version value="'$version'" />\r' description.xml
cp LPSP.uno.pkg lpsp-$version.oxt
zip -u lpsp-$version.oxt description.xml 
rm -f description.xml
