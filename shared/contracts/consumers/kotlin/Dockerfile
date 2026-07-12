FROM gradle:8.14.2-jdk21@sha256:cf0caeaac06e2824fac26daa6a55728fcb0e0e0e2ff28a430d2292547fe84dff
WORKDIR /consumer
COPY shared/contracts/consumers/kotlin ./
COPY shared/contracts /contracts
ENV WTO_CONTRACT_ROOT=/contracts
RUN ./gradlew --no-daemon test --write-locks
CMD ["./gradlew", "--no-daemon", "--offline", "test"]
