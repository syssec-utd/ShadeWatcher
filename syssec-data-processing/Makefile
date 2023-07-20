DOCKER_IMAGE=syssecutd/shadewather
VER=$(shell git describe --first-parent)
DOCKER_CONTAINER=shadewatcher
prep: FORCE
	@echo "any commands/tasks to prep docker image build"

remove:
	docker stop $(DOCKER_CONTAINER)-$(VER) || true
	docker rm $(DOCKER_CONTAINER)-$(VER) || true

build:
	docker build -t $(DOCKER_IMAGE):$(VER) .
	docker build -t $(DOCKER_IMAGE) .

push: build
	echo "Building docker images version $(VER)"
	docker push $(DOCKER_IMAGE):$(VER)
	docker push $(DOCKER_IMAGE)

run: build
	docker run --name $(DOCKER_CONTAINER) -it $(DOCKER_IMAGE) 
