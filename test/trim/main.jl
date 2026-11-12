# Compiled with `juliac --trim=safe` in CI to check that every request function
# and the webhook checks stay trim-safe. Requests go to a closed local port, so
# each one ends in a ConnectionError and nothing reaches Stripe.
using StripeClient, SHA

const SC = StripeClient

function attempt(name::String, f::F)::Bool where {F}
    try
        f()
        println(Core.stdout, name, ": unexpected answer")
        return false
    catch e
        e isa SC.ConnectionError || rethrow()
        println(Core.stdout, name, ": ", e.reason)
        return true
    end
end

function requests()::Int
    params = Dict{Symbol,Any}(:mode => "payment", :success_url => "https://example.com/paid",
        :expand => ["total_details.breakdown"], :metadata => Dict("order" => "42"),
        :line_items => [Dict{Symbol,Any}(:quantity => 1, :price => "price_1")])
    passed = 0
    passed += attempt("create_checkout_session",
        () -> SC.create_checkout_session(params; stripe_account = "acct_1", idempotency_key = "k"))
    passed += attempt("retrieve_checkout_session",
        () -> SC.retrieve_checkout_session("cs_1"; expand = ["total_details.breakdown"]))
    passed += attempt("expire_checkout_session", () -> SC.expire_checkout_session("cs_1"))
    passed += attempt("create_refund", () -> SC.create_refund(; payment_intent = "pi_1",
        amount = 100, stripe_account = "acct_1", idempotency_key = "r", refund_application_fee = true))
    passed += attempt("retrieve_refund", () -> SC.retrieve_refund("re_1"))
    passed += attempt("list_refunds", () -> SC.list_refunds(; payment_intent = "pi_1"))
    passed += attempt("refunded_total", () -> SC.refunded_total("pi_1"; stripe_account = "acct_1"))
    passed += attempt("create_account", () -> SC.create_account(Dict{Symbol,Any}(:type => "express")))
    passed += attempt("retrieve_account", () -> SC.retrieve_account("acct_1"))
    passed += attempt("create_account_link", () -> SC.create_account_link(; account = "acct_1",
        refresh_url = "https://example.com/again", return_url = "https://example.com/done",
        type = "account_onboarding"))
    passed += attempt("create_login_link", () -> SC.create_login_link("acct_1"))
    passed += attempt("create_tax_account_session", () -> SC.create_tax_account_session("acct_1"))
    passed += attempt("retrieve_tax_settings", () -> SC.retrieve_tax_settings("acct_1"))
    passed += attempt("list_tax_registrations", () -> SC.list_tax_registrations("acct_1"))
    passed += attempt("create_tax_location", () -> SC.create_tax_location("acct_1", "Gym",
        Dict{Symbol,Any}(:line1 => "1 Main St"); idempotency_key = "l"))
    passed += attempt("create_tax_product", () -> SC.create_tax_product("acct_1", "Entry",
        "txcd_20030000", "taxloc_1"; idempotency_key = "p"))
    return passed
end

function (@main)(args::Vector{String})::Cint
    passed = SC.with_stripe(requests, "sk_test_trim"; base_url = "http://127.0.0.1:1", timeout = 5)
    # oauth_token always calls connect.stripe.com, so it is compiled but not run.
    isempty(args) || attempt("oauth_token", () -> SC.oauth_token(args[1]))

    payload = "{\"id\":\"evt_1\",\"type\":\"account.updated\",\"data\":{\"object\":{}}}"
    t = string(round(Int, time()))
    signature = "t=" * t * ",v1=" * bytes2hex(hmac_sha256(Vector{UInt8}("whsec_trim"), t * "." * payload))
    event = SC.construct_webhook_event(payload, signature, "whsec_trim")
    rejected = try
        SC.construct_webhook_event(payload, signature, "whsec_other")
        false
    catch e
        e isa SC.SignatureVerificationError
    end
    println(Core.stdout, "requests ended in ConnectionError: ", passed, " of 16")
    println(Core.stdout, "webhook event: ", event.type, ", wrong secret rejected: ", rejected)
    message = SC.permanent_request_error_message(SC.ConnectionError("x"))
    println(Core.stdout, "permanent message for a ConnectionError: ", message === nothing ? "none" : message)
    return passed == 16 && rejected ? 0 : 1
end
