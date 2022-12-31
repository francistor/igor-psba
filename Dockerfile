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
RUN CGO_ENABLED=0 go build -o igor-psba

## Deploy
FROM gcr.io/distroless/base-debian11
# FROM golang:1.19-alpine
WORKDIR /

COPY --from=build /igor-psba/igor-psba /igor-psba/igor-psba
COPY --from=build /igor-psba/resources/ /igor-psba/resources/

# Create user and group yaas:yaas 1001
# RUN groupadd -r -g 1001 igor && useradd -rM -g igor -u 1001 igor && chown -R igor:igor /igor && chown -h igor:igor /igor

USER nonroot:nonroot

CMD ["/igor-psba/igor-psba", "-instance", "serverpsba"]



