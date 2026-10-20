#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { buildServer } from "./server.js";
const {server,backend}=buildServer();
const stop=()=>{backend.close();void server.close();};
process.once("SIGTERM",stop);process.once("SIGINT",stop);
process.stdin.once("end",()=>{stop();});
await server.connect(new StdioServerTransport());
