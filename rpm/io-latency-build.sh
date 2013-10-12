#!/bin/bash
##for check
cd $1
echo Starting io-latency build.
cd rpm
rpmbuild -bb io-latency.spec --define="_rpmdir $1/rpm" --define="_builddir $1/rpm" --define="_sourcedir $1/" --define="_tmppath $1/rpm"
