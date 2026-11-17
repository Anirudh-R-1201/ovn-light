FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /ovn-light ./cmd/ovn-light
FROM scratch
COPY --from=build /ovn-light /ovn-light
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/ovn-light"]
