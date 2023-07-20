PROJ=shadewatcher
DOCKER_IMAGE=syssecutd/$(PROJ)
VER=$(shell git describe --first-parent)
DOCKER_CONTAINER=$(PROJ)
prep: FORCE
	@echo "any commands/tasks to prep docker image build"
	docker volume create --name $(PROJ)

remove:
	docker stop $(DOCKER_CONTAINER) || true
	docker rm $(DOCKER_CONTAINER) || true

build:
	docker build -t $(DOCKER_IMAGE):$(VER) .
	docker build -t $(DOCKER_IMAGE) .

push: build
	echo "Building docker images version $(VER)"
	docker push $(DOCKER_IMAGE):$(VER)
	docker push $(DOCKER_IMAGE)

run: 
	docker run -h $(PROJ) --name $(DOCKER_CONTAINER) -it $(DOCKER_IMAGE) 

exec:
	docker restart $(DOCKER_CONTAINER)
	docker exec -it $(DOCKER_CONTAINER) /bin/bash
