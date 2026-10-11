FROM node:24-alpine
WORKDIR /app
RUN mkdir /state /exports && chown node:node /state /exports
COPY rui-skills/scripts/authorization-server.mjs rui-skills/scripts/gate-common.mjs ./rui-skills/scripts/
USER node
ENTRYPOINT ["node", "rui-skills/scripts/authorization-server.mjs"]
CMD ["serve", "--state-dir", "/state", "--host", "0.0.0.0"]
