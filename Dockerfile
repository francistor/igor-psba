# syntax=docker/dockerfile:1

FROM golang:1.18-alpine AS build

WORKDIR /igor-psba
# Now we are in /igor folder

# Copy dependencies...
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# ... and our code
COPY *.go ./
COPY psbahandlers/*.go ./psbahandlers/
COPY resources ./resources/
# Avoid linking externally to libc which will give a file not found error when executing
RUN CGO_ENABLED=0 go build -o igor-psba

## Deploy
FROM gcr.io/distroless/base-debian11
WORKDIR /

COPY --from=build /igor-psba/igor-psba /igor-psba/igor-psba
COPY --from=build /igor-psba/resources/ /igor-psba/resources/

USER nonroot:nonroot

# Cannot use ENTRYPOINT, which will use sh
CMD ["/igor-psba/igor-psba", "-instance", "serverpsba"]



