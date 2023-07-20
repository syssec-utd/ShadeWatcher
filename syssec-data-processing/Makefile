DOCKER_IMAGE=syssec/shadewather
VER=$(shell git describe)


prep: FORCE
	@echo "any commands/tasks to prep docker image build"

remove:
	docker stop $(DOCKER_CONTAINER)-$(VER) || true
	docker rm $(DOCKER_CONTAINER)-$(VER) || true

build:
	docker build -t $(DOCKER_IMAGE):$(VER) .
	docker build -t $(DOCKER_IMAGE) .

