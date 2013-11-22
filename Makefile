.PHONY: build doc install test setup reinstall clean distclean
all: build

NAME=pcap-format
J=4
OFLAGS ?= -classic-display
TIME = $(shell bash -c "echo $$(date +%Y%m%d-%H%M%S)")

UNIX ?= $(shell if ocamlfind query lwt.unix >/dev/null 2>&1; then echo --enable-unix; fi)
MIRAGE ?= $(shell if ocamlfind query mirage-net >/dev/null 2>&1; then echo --enable-mirage; fi)

## temporarily disable unit tests
TESTS ?= --disable-tests # $(shell if ocamlfind query oUnit >/dev/null && ocamlfind query lwt.unix >/dev/null 2>&1; then echo --enable-tests; fi)

setup.ml: _oasis
	oasis setup

setup.data: setup.ml
	ocaml setup.ml -configure $(UNIX) $(MIRAGE) $(TESTS)

build: setup
	ocaml setup.ml -build -j $(J) $(OFLAGS)

doc: setup.data setup.ml
	ocaml setup.ml -doc -j $(J) $(OFLAGS)

install: setup.data setup.ml
	ocaml setup.ml -install $(OFLAGS)

test:
	./_build/lib_test/test.native

setup: setup.ml setup.data
	echo "<**/*.ml{,i}>: syntax_camlp4o, pkg_camlp4" >> _tags

reinstall: setup.ml
	ocamlfind remove $(NAME) || true
	ocaml setup.ml -reinstall

clean:
	ocamlbuild -clean
	$(RM) setup.data setup.log
	$(RM) flows.native print.native packed_flow.native

distclean: clean
	$(RM) setup.ml myocamlbuild.ml lib/capture.* _tags
	# mv _tags _tags.$(TIME)
