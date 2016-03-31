# Env preparations
if ! id -u builder &>/dev/null ; then
	sudo adduser builder
	runuser -l builder -c "mkdir -p ~/rpmbuild/{RPMS,SOURCES,SPECS,SRPMS}"
	passwd -d root
	yum install mock
fi

KUBE_SRC=$PWD # Or replace with your locaction if you are building out of tree

# Cleanup
#runuser -l builder -c "rm -rf /home/builder/rpmbuild"
#runuser -l builder -c "mkdir -p ~/rpmbuild/{RPMS,SOURCES,SPECS,SRPMS}"
runuser -l builder -c "rm -rf ~/rpmbuild/*/*"

# Prepare
cd $KUBE_SRC
VERSION=`grep "%global kube_version" rpm/kubernetes.spec | awk '{print $3}'`

# TODO exclude rpm dir
git archive `git rev-parse --abbrev-ref HEAD` --prefix "kubernetes-$VERSION/" | gzip > kubernetes-$VERSION.tar.gz
mv kubernetes-$VERSION.tar.gz /home/builder/rpmbuild/SOURCES/
cp rpm/* /home/builder/rpmbuild/SOURCES/
mv /home/builder/rpmbuild/{SOURCES,SPECS}/kubernetes.spec

# Build
runuser -l builder -c "mock -r epel-7-x86_64 --spec ~/rpmbuild/SPECS/kubernetes.spec --sources=~/rpmbuild/SOURCES --resultdir=~/rpmbuild/SRPMS --buildsrpm"
runuser -l builder -c "setarch x86_64 mock -r epel-7-x86_64 rebuild /home/builder/rpmbuild/SRPMS/*.rpm --resultdir=/home/builder/rpmbuild/RPMS"

echo " =========== Find RPMs at /home/builder/rpmbuild/RPMS =========== "
ls /home/builder/rpmbuild/RPMS

cd -
