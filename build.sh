#!/bin/bash

mkdir -p ./data/{results,log}

if !(command -v dep)
then
  curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
fi


mkdir -p $GOPATH/src/github.com/kotakanbe
mkdir -p $GOPATH/src/github.com/future-architect


cd $GOPATH/src/github.com/kotakanbe
if [ ! -d go-cpe-dictionary ]
then
  git clone https://github.com/kotakanbe/go-cpe-dictionary.git
  git reset --hard 734a95bbaac7530f3dbf4ad7bd6bfac4e4e0abc7
fi
cd go-cpe-dictionary
make install


cd $GOPATH/src/github.com/kotakanbe
if [ ! -d go-cve-dictionary ]
then
  git clone https://github.com/kotakanbe/go-cve-dictionary.git
  git reset --hard c2bcc418e037d6bc2d6b47c2d782900126b4f884
fi
cd go-cve-dictionary
make install


cd $GOPATH/src/github.com/kotakanbe
if [ ! -d goval-dictionary ]
then
  git clone https://github.com/kotakanbe/goval-dictionary.git
  git reset --hard c462c07a5cd0b6de52f167e9aa4298083edfc356
fi
cd goval-dictionary
make install


cd $GOPATH/src/github.com/future-architect
if [ ! -d vuls ]
then
  git clone https://github.com/future-architect/vuls.git
  git reset --hard ea800e04bc415b11546f2bc5f074ab9459c75295
fi
cd vuls
make install

mkdir -p ./bin
cp $GOPATH/bin/{goval-dictionary,vuls,go-cve-dictionary} ./bin/
