FROM swift:6.1.2-jammy@sha256:5910655d205a5a54b0b9efdf72c4066a8de1932513fdc81793e2544b5d5a0709
WORKDIR /consumer
COPY shared/contracts/consumers/swift ./
COPY shared/contracts /contracts
ENV WTO_CONTRACT_ROOT=/contracts
CMD ["swift", "test", "--parallel"]
