# tpay-webhook-auth

[![NPM version](https://img.shields.io/npm/v/tpay-webhook-auth)](https://www.npmjs.com/package/tpay-webhook-auth)
[![NPM downloads](https://img.shields.io/npm/dm/tpay-webhook-auth)](https://www.npmjs.com/package/tpay-webhook-auth)
[![NPM bundle size](https://img.shields.io/bundlephobia/min/tpay-webhook-auth)](https://www.npmjs.com/package/tpay-webhook-auth)

## Description

Tpay JWS signature verification tool to ensure notification comes from tpay.com notification service.

-   TypeScript support
-   Lightweight - no external dependencies
-   Caches the root certificate and refreshes it automatically when needed

Access to the raw body is required to verify the signature. Example using "express":

```typescript
import express, { raw } from "express";

const app = express();
app.use("/tpay-notification-webhook", raw({ type: "application/x-www-form-urlencoded" }));
```

## Requirements

-   Node.js v18.0.0 or higher

## Examples

### NestJS Guard

```typescript
import { CanActivate, ExecutionContext, Injectable } from "@nestjs/common";
import { Request } from "express";
import { TpayWebhookAuth } from "tpay-webhook-auth";

@Injectable()
export class TpayWebhookGuard implements CanActivate {
    private readonly auth = new TpayWebhookAuth(); // create only one instance to reuse the cached root certificate

    public async canActivate(context: ExecutionContext) {
        const req = context.switchToHttp().getRequest<Request>();

        const signature = req.headers["x-jws-signature"];

        return this.auth.checkSignature(req.body, signature);
    }
}
```

### Express Middleware

```typescript
import { NextFunction, Request, Response } from "express";
import { TpayWebhookAuth } from "tpay-webhook-auth";

const auth = new TpayWebhookAuth(); // create only one instance to reuse the cached root certificate

export async function tpayWebhookMiddleware(req: Request, res: Response, next: NextFunction) {
    const signature = req.headers["x-jws-signature"];

    if (!(await auth.checkSignature(req.body, signature))) {
        return res.status(403).send("Invalid signature");
    }

    next();
}
```
