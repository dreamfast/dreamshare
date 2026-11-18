# Stage 1: build the SPA
FROM node:22-alpine AS spa
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ .
RUN npx vite build

# Stage 2: build the Go binary with the embedded SPA
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=spa /web/dist /src/internal/webdist/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/dreamshare ./cmd/dreamshare

# Stage 3: minimal runtime
# the deploy runbook pins this by digest for production
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/dreamshare /dreamshare
ENV SQLITE_PATH=/data/dreamshare.db
USER nonroot
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/dreamshare"]
