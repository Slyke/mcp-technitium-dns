## Image Publishing

Use a version tag and a commit-specific tag for every pushed image. The version tag is convenient for humans, while the version-plus-hash tag is the precise deployment and rollback target.

```bash
USERNAME=YOURUSERNAME
DOMAIN=registry.example.com
IMAGE_NAME=mcp-technitium-dns
# VERSION="dev"
VERSION=v0.0.1

git tag -a "$VERSION" -m "$VERSION"
# git tag -d "$VERSION"
git push origin "$VERSION"
# git push --force origin "$VERSION"

SHA=$(git rev-parse --short=12 HEAD)

docker build -t "$IMAGE_NAME:build" -f ./Dockerfile .

# docker tag "$IMAGE_NAME:build" "$USERNAME/$IMAGE_NAME:latest"
# docker tag "$IMAGE_NAME:build" "$DOMAIN/$USERNAME/$IMAGE_NAME:latest"
# docker push "$USERNAME/$IMAGE_NAME:latest"
# docker push "$DOMAIN/$USERNAME/$IMAGE_NAME:latest"

for TAG in latest "$VERSION" "$VERSION-$SHA"; do
  docker tag "$IMAGE_NAME:build" "$USERNAME/$IMAGE_NAME:$TAG"
  docker tag "$IMAGE_NAME:build" "$DOMAIN/$USERNAME/$IMAGE_NAME:$TAG"
  docker push "$USERNAME/$IMAGE_NAME:$TAG"
  docker push "$DOMAIN/$USERNAME/$IMAGE_NAME:$TAG"
done
```
