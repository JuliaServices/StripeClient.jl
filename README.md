# StripeClient.jl

[![CI](https://github.com/JuliaServices/StripeClient.jl/actions/workflows/ci.yml/badge.svg)](https://github.com/JuliaServices/StripeClient.jl/actions/workflows/ci.yml)

Call Stripe's API from a Julia server: Checkout Sessions, refunds, Connect
accounts (onboarding links, dashboard links, OAuth), Stripe Tax for connected
accounts, and webhook signature checks. Answers parse into typed structs.

It covers the slice of Stripe that a platform taking payments for other
businesses needs, and grows as callers need more.

## Use

Set the secret key for a block of code; every request inside uses it.

```julia
using StripeClient

StripeClient.with_stripe(ENV["STRIPE_SECRET_KEY"]) do
    session = StripeClient.create_checkout_session(Dict{Symbol,Any}(
            :mode => "payment",
            :success_url => "https://example.com/paid",
            :line_items => [Dict{Symbol,Any}(:quantity => 1, :price_data => Dict{Symbol,Any}(
                :currency => "usd", :unit_amount => 2500,
                :product_data => Dict{Symbol,Any}(:name => "Entry fee")))]);
        stripe_account = "acct_123",       # a direct charge on a connected account
        idempotency_key = "order-42")      # safe to send again
    session.url                            # send the payer here
end
```

Parameters are Stripe's own, as a `Dict{Symbol,Any}`; nested dictionaries and
vectors become Stripe's bracket notation (`StripeClient.form_params` shows the
fields a dictionary turns into).

Request functions: `create_checkout_session`, `retrieve_checkout_session`,
`expire_checkout_session`, `create_refund`, `retrieve_refund`, `list_refunds`,
`refunded_total`, `create_account`, `retrieve_account`, `create_account_link`,
`create_login_link`, `oauth_token`, `create_tax_account_session`,
`retrieve_tax_settings`, `list_tax_registrations`, `create_tax_location`, and
`create_tax_product`.

Webhooks:

```julia
event = StripeClient.construct_webhook_event(String(req.body),
    HTTP.header(req, "Stripe-Signature"), ENV["STRIPE_WEBHOOK_SECRET"])
```

## Errors

- `StripeClient.AuthenticationError`: Stripe refused the API key (HTTP 401 or
  403). The server's configuration is wrong; don't pass the 401 on to your own
  client.
- `StripeClient.ConnectionError`: Stripe could not be reached or did not answer
  in time (10 s to connect, 30 s in all; set `timeout` on `with_stripe`). Retry
  POSTs with the same `idempotency_key`.
- `StripeClient.SignatureVerificationError`: a webhook's signature does not
  match.
- Any other refusal is an `HTTP.StatusError`.
  `StripeClient.permanent_request_error_message(e)` returns Stripe's message when
  sending the request again would fail the same way (HTTP 400, 402, or 404), and
  `nothing` when a retry might work.

## Trimming

The package compiles with `juliac --trim=safe` on Julia 1.14 and later; CI
builds and runs `test/trim/main.jl` to keep it that way. On Julia 1.13 the
verifier rejects Base's ScopedValues update, which `with_stripe` uses.
