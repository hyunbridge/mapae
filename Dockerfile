# Stage 1: Builder
FROM --platform=$BUILDPLATFORM golang:1.25-trixie AS builder

WORKDIR /src

ARG BUILDPLATFORM
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-$(go env GOARCH)} go build -trimpath -ldflags="-s -w" -o /out/mapae ./cmd/mapae

# Stage 2: Runtime - Distroless
FROM gcr.io/distroless/static-debian13:nonroot

WORKDIR /app

COPY --from=builder /out/mapae /app/mapae

EXPOSE 2525 8000

ENTRYPOINT ["/app/mapae"]
