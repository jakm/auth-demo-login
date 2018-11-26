FROM golang:alpine AS build
ADD . /go/src/github.com/jakm/auth-demo-login
RUN go install github.com/jakm/auth-demo-login

FROM alpine
RUN apk add ca-certificates
COPY --from=build /go/bin/auth-demo-login /opt/auth-demo-login/auth-demo-login
ADD config.yaml /opt/auth-demo-login/config.yaml
ADD cert /opt/auth-demo-login/cert
ADD templates /opt/auth-demo-login/templates
WORKDIR /opt/auth-demo-login
CMD /opt/auth-demo-login/auth-demo-login
