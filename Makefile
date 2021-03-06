FILES_TO_RPM = dfs2cernboxd dfs2cernboxd.yaml dfs2cernboxd.service dfs2cernboxd.logrotate
SPECFILE = $(shell find . -type f -name *.spec)
PACKAGE  = $(shell awk '$$1 == "Name:"     { print $$2 }' $(SPECFILE) )
VERSION  = $(shell awk '$$1 == "Version:"  { print $$2 }' $(SPECFILE) )
RELEASE  = $(shell awk '$$1 == "Release:"  { print $$2 }' $(SPECFILE) )
rpmbuild = ${shell pwd}/rpmbuild

clean:
	@rm -rf $(PACKAGE)-$(VERSION)
	@rm -rf $(rpmbuild)
	@rm -rf *rpm
	@rm -rf dfs2cernboxd

rpmdefines=--define='_topdir ${rpmbuild}' \
        --define='_sourcedir %{_topdir}/SOURCES' \
        --define='_builddir %{_topdir}/BUILD' \
        --define='_srcrpmdir %{_topdir}/SRPMS' \
        --define='_rpmdir %{_topdir}/RPMS'

dist: clean
#	dep ensure
	go get
	go build 
	@mkdir -p $(PACKAGE)-$(VERSION)
	@cp -r $(FILES_TO_RPM) $(PACKAGE)-$(VERSION)
	tar cpfz ./$(PACKAGE)-$(VERSION).tar.gz $(PACKAGE)-$(VERSION)

prepare: dist
	@mkdir -p $(rpmbuild)/RPMS/x86_64
	@mkdir -p $(rpmbuild)/SRPMS/
	@mkdir -p $(rpmbuild)/SPECS/
	@mkdir -p $(rpmbuild)/SOURCES/
	@mkdir -p $(rpmbuild)/BUILD/
	@mv $(PACKAGE)-$(VERSION).tar.gz $(rpmbuild)/SOURCES 
	@cp $(SPECFILE) $(rpmbuild)/SOURCES 

srpm: prepare $(SPECFILE)
	rpmbuild --nodeps -bs $(rpmdefines) $(SPECFILE)
	#cp $(rpmbuild)/SRPMS/* .

rpm: srpm
	rpmbuild --nodeps -bb $(rpmdefines) $(SPECFILE)
	cp $(rpmbuild)/RPMS/x86_64/* .

build:
	docker build -t cbox_rpm_builder_img .
	docker run --rm -it -v ${CURDIR}:/root/go/src/github.com/cernbox/dfs2cernboxd -w /root/go/src/github.com/cernbox/dfs2cernboxd cbox_rpm_builder_img bash -lc "make rpm"
