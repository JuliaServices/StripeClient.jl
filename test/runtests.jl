using Test, StripeClient, HTTP, JSON, SHA, Sockets

const SC = StripeClient
const KEY = "sk_test_123"

const CHECKOUT_SESSION = """
{
  "id": "cs_test_a1",
  "object": "checkout.session",
  "mode": "payment",
  "status": "complete",
  "payment_status": "paid",
  "url": null,
  "success_url": "https://example.com/paid",
  "cancel_url": "https://example.com/cancel",
  "client_reference_id": "order-42",
  "customer": null,
  "customer_email": "pat@example.com",
  "customer_creation": "if_required",
  "amount_subtotal": 2500,
  "amount_total": 2683,
  "currency": "usd",
  "payment_intent": "pi_3Abc",
  "payment_method_types": ["card"],
  "subscription": null,
  "metadata": {"order": "42"},
  "created": 1762900000,
  "expires_at": 1762986400,
  "livemode": false,
  "allow_promotion_codes": null,
  "automatic_tax": {"enabled": true, "liability": {"type": "self"}, "status": "complete"},
  "total_details": {
    "amount_discount": 0,
    "amount_shipping": null,
    "amount_tax": 183,
    "breakdown": {
      "discounts": [],
      "taxes": [{
        "amount": 183,
        "taxable_amount": null,
        "taxability_reason": "standard_rated",
        "rate": {
          "id": "txr_1", "object": "tax_rate", "display_name": "Sales Tax",
          "effective_percentage": 7.3, "percentage": 7.3, "inclusive": false,
          "jurisdiction": "Utah", "jurisdiction_level": "state",
          "state": "UT", "country": "US", "tax_type": "sales_tax"
        }
      }]
    }
  }
}
"""

const ACCOUNT = """
{
  "id": "acct_1",
  "object": "account",
  "type": "express",
  "business_type": "individual",
  "business_profile": {"mcc": "7997", "name": "Rec League", "url": null},
  "capabilities": {"card_payments": "active", "transfers": "active"},
  "charges_enabled": true,
  "country": "US",
  "created": 1762900000,
  "default_currency": "usd",
  "details_submitted": true,
  "email": "owner@example.com",
  "metadata": {"org_id": "ORG1"},
  "payouts_enabled": false,
  "requirements": {
    "current_deadline": null,
    "currently_due": ["external_account"],
    "disabled_reason": "requirements.past_due",
    "errors": [],
    "eventually_due": ["external_account"],
    "past_due": ["external_account"],
    "pending_verification": []
  }
}
"""

refund(id, status, amount) = """{"id": "$id", "object": "refund", "amount": $amount,
    "currency": "usd", "payment_intent": "pi_1", "charge": "ch_1", "status": "$status",
    "failure_reason": null, "reason": null, "created": 1762900000, "metadata": {}}"""

refund_page(has_more, refunds...) =
    """{"object": "list", "url": "/v1/refunds", "has_more": $has_more, "data": [$(join(refunds, ","))]}"""

# Runs `f(seen)` inside `with_stripe`, pointed at a local server that answers
# every request with `answer(method, target)` (a status and a JSON body) and
# records each request in `seen`.
function with_stub(f, answer)
    port, listener = Sockets.listenany(Sockets.localhost, 0)
    close(listener)
    seen = NamedTuple[]
    server = HTTP.serve!("127.0.0.1", port) do req
        headers = Dict(name => HTTP.header(req, name, "") for name in
            ("Authorization", "Content-Type", "Idempotency-Key", "Stripe-Account", "Stripe-Version"))
        push!(seen, (; method = req.method, target = req.target, body = String(req.body), headers))
        status, body = answer(req.method, req.target)
        return HTTP.Response(status, ["Content-Type" => "application/json"], body)
    end
    try
        return SC.with_stripe(() -> f(seen), KEY; base_url = "http://127.0.0.1:$port")
    finally
        close(server)
    end
end

ok(body) = (method, target) -> (200, body)

function signed(payload; secret = "whsec_test", t = round(Int, time()))
    return "t=$t,v1=" * bytes2hex(hmac_sha256(Vector{UInt8}(secret), "$t.$payload"))
end

@testset "StripeClient" begin
    @testset "form parameters use Stripe's bracket notation" begin
        params = Dict{Symbol,Any}(
            :mode => "payment",
            :kind => :express,
            :rate => 7.5,
            :skip => nothing,
            :expand => ["total_details.breakdown", "payment_intent"],
            :metadata => Dict("order" => "42"),
            :automatic_tax => Dict{Symbol,Any}(:enabled => true),
            :custom_text => Dict{Symbol,String}(:submit => "Pay"),
            :payment_intent_data => Dict{Symbol,Int}(:application_fee_amount => 100),
            :line_items => [Dict{Symbol,Any}(:quantity => 2,
                :price_data => Dict{Symbol,Any}(:unit_amount => 1250, :currency => "usd"))],
            :mixed => Any["a", Dict{Symbol,Any}(:b => false)],
        )
        fields = SC.form_params(params)
        @test Set(fields) == Set([
            "mode" => "payment", "kind" => "express", "rate" => "7.5",
            "expand[]" => "total_details.breakdown", "expand[]" => "payment_intent",
            "metadata[order]" => "42", "automatic_tax[enabled]" => "true",
            "custom_text[submit]" => "Pay",
            "payment_intent_data[application_fee_amount]" => "100",
            "line_items[0][quantity]" => "2",
            "line_items[0][price_data][unit_amount]" => "1250",
            "line_items[0][price_data][currency]" => "usd",
            "mixed[0]" => "a", "mixed[1][b]" => "false"])
        @test [v for (k, v) in fields if k == "expand[]"] == ["total_details.breakdown", "payment_intent"]
        @test_throws ArgumentError SC.form_params(Dict{Symbol,Any}(:bad => 1 // 2))
    end

    @testset "requests carry the key, account, version, and idempotency headers" begin
        with_stub(ok(CHECKOUT_SESSION)) do seen
            session = SC.create_checkout_session(Dict{Symbol,Any}(
                    :mode => "payment",
                    :success_url => "https://example.com/paid?a=1&b=2",
                    :line_items => [Dict{Symbol,Any}(:quantity => 1, :price => "price_1")]);
                stripe_account = "acct_1", idempotency_key = "order-42")
            request = only(seen)
            @test request.method == "POST"
            @test request.target == "/v1/checkout/sessions"
            @test request.headers["Authorization"] == "Bearer $KEY"
            @test request.headers["Content-Type"] == "application/x-www-form-urlencoded"
            @test request.headers["Idempotency-Key"] == "order-42"
            @test request.headers["Stripe-Account"] == "acct_1"
            @test request.headers["Stripe-Version"] == ""
            @test Set(split(request.body, '&')) == Set([
                "mode=payment",
                "success_url=https%3A%2F%2Fexample.com%2Fpaid%3Fa%3D1%26b%3D2",
                "line_items%5B0%5D%5Bquantity%5D=1",
                "line_items%5B0%5D%5Bprice%5D=price_1"])

            @test session.id == "cs_test_a1"
            @test session.payment_status == "paid"
            @test session.amount_total == 2683
            @test session.metadata == Dict("order" => "42")
            @test session.automatic_tax.enabled
            @test session.total_details.amount_tax == 183
            tax = only(session.total_details.breakdown.taxes)
            @test tax.amount == 183
            @test tax.taxable_amount === nothing
            @test session.total_details.amount_shipping === nothing
            @test tax.rate.jurisdiction == "Utah"
            @test tax.rate.effective_percentage == 7.3

            SC.retrieve_checkout_session("cs_test_a1"; expand = ["total_details.breakdown"],
                                         stripe_account = "acct_1")
            @test seen[2].method == "GET"
            @test seen[2].target == "/v1/checkout/sessions/cs_test_a1?expand%5B%5D=total_details.breakdown"
            @test seen[2].body == ""
            @test seen[2].headers["Idempotency-Key"] == ""

            SC.expire_checkout_session("cs_test_a1")
            @test (seen[3].method, seen[3].target) == ("POST", "/v1/checkout/sessions/cs_test_a1/expire")
            @test seen[3].headers["Stripe-Account"] == ""
        end
    end

    @testset "each request goes to its Stripe endpoint and parses its answer" begin
        answers = Dict(
            "/v1/accounts" => ACCOUNT,
            "/v1/accounts/acct_1" => ACCOUNT,
            "/v1/account_links" => """{"object": "account_link", "url": "https://connect.stripe.com/setup/e/acct_1/x", "created": 1762900000, "expires_at": 1762900300}""",
            "/v1/accounts/acct_1/login_links" => """{"object": "login_link", "url": "https://connect.stripe.com/express/x", "created": 1762900000}""",
            "/v1/account_sessions" => """{"object": "account_session", "account": "acct_1", "client_secret": "accs_secret_x", "expires_at": 1762901800, "livemode": false, "components": {}}""",
            "/v1/tax/settings" => """{"object": "tax.settings", "status": "pending", "status_details": {"pending": {"missing_fields": ["head_office"]}}, "defaults": {"tax_behavior": null, "tax_code": "txcd_10000000"}, "head_office": null, "livemode": false}""",
            "/v1/tax/registrations" => """{"object": "list", "url": "/v1/tax/registrations", "has_more": false, "data": [{"id": "taxreg_1", "object": "tax.registration", "country": "US", "country_options": {"us": {"state": "UT", "type": "state_sales_tax"}}, "status": "active", "active_from": 1762900000, "expires_at": null, "livemode": false}]}""",
            "/v1/tax/locations" => """{"id": "taxloc_1", "object": "tax.location", "type": "performance", "description": "Main gym", "address": {"line1": "1 Main St", "city": "Provo", "state": "UT", "postal_code": "84601", "country": "US"}}""",
            "/v1/products" => """{"id": "prod_1", "object": "product", "name": "Entry", "active": true, "tax_code": "txcd_20030000", "metadata": {"event": "E1"}, "images": [], "livemode": false}""",
            "/v1/refunds" => refund("re_1", "pending", 700),
            "/v1/refunds/re_1" => refund("re_1", "succeeded", 700),
        )
        with_stub((method, target) -> (200, answers[first(split(target, '?'))])) do seen
            account = SC.create_account(Dict{Symbol,Any}(:type => "express",
                :capabilities => Dict{Symbol,Any}(:transfers => Dict{Symbol,Any}(:requested => true)),
                :metadata => Dict("org_id" => "ORG1")))
            @test Set(split(seen[end].body, '&')) == Set(["type=express",
                "capabilities%5Btransfers%5D%5Brequested%5D=true", "metadata%5Borg_id%5D=ORG1"])
            @test account.charges_enabled === true
            @test account.payouts_enabled === false
            @test account.metadata == Dict("org_id" => "ORG1")
            @test account.requirements["currently_due"] == ["external_account"]
            @test account.requirements["current_deadline"] === nothing

            @test SC.retrieve_account("acct_1").type == "express"
            @test seen[end].method == "GET"

            link = SC.create_account_link(; account = "acct_1", refresh_url = "https://example.com/again",
                return_url = "https://example.com/done", type = "account_onboarding")
            @test link.url == "https://connect.stripe.com/setup/e/acct_1/x"
            @test occursin("type=account_onboarding", seen[end].body)

            @test SC.create_login_link("acct_1").url == "https://connect.stripe.com/express/x"
            @test seen[end].target == "/v1/accounts/acct_1/login_links"

            session = SC.create_tax_account_session("acct_1")
            @test (session.account, session.client_secret) == ("acct_1", "accs_secret_x")
            @test occursin("components%5Btax_registrations%5D%5Benabled%5D=true", seen[end].body)

            settings = SC.retrieve_tax_settings("acct_1")
            @test settings.status == "pending"
            @test settings.status_details.pending.missing_fields == ["head_office"]
            @test seen[end].headers["Stripe-Account"] == "acct_1"
            @test JSON.parse("""{"object": "tax.settings", "status": "pending", "livemode": false,
                "status_details": {"pending": {"missing_fields": null}}}""",
                SC.TaxSettings).status_details.pending.missing_fields === nothing

            registration = only(SC.list_tax_registrations("acct_1").data)
            @test registration.country_options.us.state == "UT"
            @test registration.country_options.us.type == "state_sales_tax"

            location = SC.create_tax_location("acct_1", "Main gym",
                Dict{Symbol,Any}(:line1 => "1 Main St", :country => "US"); idempotency_key = "venue-1")
            @test (location.id, location.type, location.description) == ("taxloc_1", "performance", "Main gym")
            @test seen[end].headers["Stripe-Version"] == SC.TAX_API_VERSION
            @test seen[end].headers["Idempotency-Key"] == "venue-1"
            @test Set(split(seen[end].body, '&')) == Set(["type=performance", "description=Main%20gym",
                "address%5Bline1%5D=1%20Main%20St", "address%5Bcountry%5D=US"])

            product = SC.create_tax_product("acct_1", "Entry", "txcd_20030000", "taxloc_1";
                metadata = Dict("event" => "E1"))
            @test product.tax_code == "txcd_20030000"
            @test seen[end].headers["Stripe-Version"] == SC.TAX_API_VERSION
            @test occursin("tax_details%5Bperformance_location%5D=taxloc_1", seen[end].body)

            pending = SC.create_refund(; payment_intent = "pi_1", amount = 700,
                stripe_account = "acct_1", idempotency_key = "refund-1", refund_application_fee = true)
            @test pending.status == "pending"
            @test Set(split(seen[end].body, '&')) ==
                Set(["payment_intent=pi_1", "amount=700", "refund_application_fee=true"])
            SC.create_refund(; payment_intent = "pi_1")
            @test seen[end].body == "payment_intent=pi_1"

            @test SC.retrieve_refund("re_1"; stripe_account = "acct_1").status == "succeeded"
        end
    end

    @testset "a session's line items carry their own taxes" begin
        line_items = """
        {"object": "list", "url": "/v1/checkout/sessions/cs_1/line_items", "has_more": false, "data": [
          {"id": "li_1", "object": "item", "amount_subtotal": 2500, "amount_discount": 250,
           "amount_tax": 164, "amount_total": 2414, "currency": "usd", "description": "Spring league",
           "quantity": 1,
           "price": {"id": "price_1", "object": "price", "product": "prod_1", "unit_amount": 2500,
                     "currency": "usd", "type": "one_time"},
           "taxes": [{"amount": 164, "taxable_amount": 2250, "taxability_reason": "standard_rated",
                      "rate": {"id": "txr_1", "object": "tax_rate", "display_name": "Sales Tax",
                               "percentage": 7.3, "jurisdiction": "Utah", "state": "UT",
                               "country": "US", "tax_type": "sales_tax"}}]},
          {"id": "li_2", "object": "item", "amount_subtotal": 130, "amount_discount": 0,
           "amount_tax": 0, "amount_total": 130, "currency": "usd", "description": "Fee",
           "quantity": 1, "price": {"id": "price_2", "product": "prod_2", "unit_amount": 130},
           "taxes": []}
        ]}
        """
        with_stub(ok(line_items)) do seen
            page = SC.list_checkout_session_line_items("cs_1"; stripe_account = "acct_1")
            request = only(seen)
            @test request.method == "GET"
            path, query = split(request.target, '?')
            @test path == "/v1/checkout/sessions/cs_1/line_items"
            @test Set(split(query, '&')) == Set(["limit=100", "expand%5B%5D=data.taxes"])
            @test request.headers["Stripe-Account"] == "acct_1"
            first_line, fee_line = page.data
            @test (first_line.amount_subtotal, first_line.amount_discount,
                   first_line.amount_tax, first_line.amount_total) == (2500, 250, 164, 2414)
            @test first_line.price.product == "prod_1"
            tax = only(first_line.taxes)
            @test (tax.amount, tax.taxable_amount, tax.taxability_reason) == (164, 2250, "standard_rated")
            @test tax.rate.jurisdiction == "Utah"
            @test isempty(fee_line.taxes)

            SC.list_checkout_session_line_items("cs_1"; limit = 2, starting_after = "li_2")
            @test occursin("starting_after=li_2", seen[2].target)
            @test occursin("limit=2", seen[2].target)
        end
    end

    @testset "a charge names its application fee, which the platform reads and refunds" begin
        charges = """
        {"object": "list", "url": "/v1/charges", "has_more": false, "data": [
          {"id": "ch_1", "object": "charge", "amount": 5260, "amount_captured": 5260,
           "amount_refunded": 0, "currency": "usd", "status": "succeeded", "paid": true,
           "refunded": false, "payment_intent": "pi_1", "application_fee": "fee_1",
           "application_fee_amount": 260, "created": 1762900000,
           "balance_transaction": "txn_1", "outcome": {"type": "authorized"}}
        ]}
        """
        fee = """{"id": "fee_1", "object": "application_fee", "amount": 260, "amount_refunded": 130,
                  "refunded": false, "currency": "usd", "account": "acct_1", "charge": "ch_1",
                  "created": 1762900000, "refunds": {"object": "list", "data": []}}"""
        fee_refund = """{"id": "fr_1", "object": "fee_refund", "amount": 130, "currency": "usd",
                         "fee": "fee_1", "created": 1762900100, "metadata": {"payment": "P1"},
                         "balance_transaction": "txn_2"}"""
        answers = Dict("/v1/charges" => charges, "/v1/application_fees/fee_1" => fee,
                       "/v1/application_fees/fee_1/refunds" => fee_refund)
        with_stub((method, target) -> (200, answers[first(split(target, '?'))])) do seen
            charge = only(SC.list_charges(; payment_intent = "pi_1", stripe_account = "acct_1").data)
            @test seen[1].method == "GET"
            @test occursin("payment_intent=pi_1", seen[1].target)
            @test seen[1].headers["Stripe-Account"] == "acct_1"
            @test (charge.status, charge.application_fee, charge.application_fee_amount) ==
                  ("succeeded", "fee_1", 260)
            SC.list_charges(; payment_intent = "pi_1", limit = 1, starting_after = "ch_2")
            @test occursin("starting_after=ch_2", seen[2].target)
            @test occursin("limit=1", seen[2].target)

            platform_fee = SC.retrieve_application_fee("fee_1")
            @test (seen[3].method, seen[3].target) == ("GET", "/v1/application_fees/fee_1")
            @test seen[3].headers["Stripe-Account"] == ""
            @test (platform_fee.amount, platform_fee.amount_refunded, platform_fee.account) ==
                  (260, 130, "acct_1")

            refunded = SC.create_application_fee_refund("fee_1"; amount = 130,
                idempotency_key = "P1-fee", metadata = Dict("payment" => "P1"))
            @test (seen[4].method, seen[4].target) == ("POST", "/v1/application_fees/fee_1/refunds")
            @test seen[4].headers["Stripe-Account"] == ""
            @test seen[4].headers["Idempotency-Key"] == "P1-fee"
            @test Set(split(seen[4].body, '&')) == Set(["amount=130", "metadata%5Bpayment%5D=P1"])
            @test (refunded.id, refunded.amount, refunded.fee) == ("fr_1", 130, "fee_1")

            SC.create_application_fee_refund("fee_1")
            @test seen[5].body == ""
        end
    end

    @testset "succeeded_charge looks through every page of charges" begin
        charge(id, status) = """{"id": "$id", "object": "charge", "status": "$status", "application_fee": "fee_$id"}"""
        first_page = """{"object": "list", "has_more": true, "data": [$(charge("ch_3", "failed")), $(charge("ch_2", "failed"))]}"""
        second_page = """{"object": "list", "has_more": false, "data": [$(charge("ch_1", "succeeded"))]}"""
        with_stub((method, target) -> (200, occursin("starting_after=ch_2", target) ? second_page : first_page)) do seen
            found = SC.succeeded_charge("pi_1"; stripe_account = "acct_1")
            @test found.id == "ch_1"
            @test found.application_fee == "fee_ch_1"
            @test length(seen) == 2
            @test all(r -> r.headers["Stripe-Account"] == "acct_1", seen)
        end
        with_stub(ok("""{"object": "list", "has_more": false, "data": []}""")) do seen
            @test SC.succeeded_charge("pi_2") === nothing
        end
    end

    @testset "refunded_total sums succeeded refunds across pages" begin
        first_page = refund_page(true, refund("re_1", "succeeded", 500), refund("re_2", "failed", 300))
        last_page = refund_page(false, refund("re_3", "succeeded", 200), refund("re_4", "pending", 100))
        page(target) = occursin("starting_after=re_2", target) ? last_page : first_page
        with_stub((method, target) -> (200, page(target))) do seen
            @test SC.refunded_total("pi_1"; stripe_account = "acct_1") == 700
            @test length(seen) == 2
            for request in seen
                query = Set(split(last(split(request.target, '?')), '&'))
                @test "payment_intent=pi_1" in query && "limit=100" in query
                @test request.headers["Stripe-Account"] == "acct_1"
            end
        end
    end

    @testset "Stripe's refusals become typed errors" begin
        stripe_error(message) = """{"error": {"message": "$message", "type": "invalid_request_error"}}"""
        for status in (401, 403)
            with_stub((m, t) -> (status, stripe_error("Invalid API Key provided: sk_test_***123"))) do seen
                err = try SC.retrieve_account("acct_1"); nothing catch e; e end
                @test err isa SC.AuthenticationError
                @test err.status == status
                @test err.message == "Invalid API Key provided: sk_test_***123"
                @test occursin("HTTP $status", sprint(showerror, err))
            end
        end

        with_stub((m, t) -> (400, stripe_error("Refund amount exceeds the charge"))) do seen
            err = try SC.create_refund(; payment_intent = "pi_1", amount = 9999); nothing catch e; e end
            @test err isa HTTP.StatusError
            @test SC.permanent_request_error_message(err) == "Refund amount exceeds the charge"
        end
        with_stub((m, t) -> (404, "not json")) do seen
            err = try SC.retrieve_refund("re_missing"); nothing catch e; e end
            @test SC.permanent_request_error_message(err) == "Stripe rejected the request (HTTP 404)"
        end
        @test SC.permanent_request_error_message(HTTP.StatusError(HTTP.Response(500, "{}"))) === nothing
        @test SC.permanent_request_error_message(HTTP.StatusError(HTTP.Response(429, "{}"))) === nothing
        @test SC.permanent_request_error_message(ErrorException("boom")) === nothing
    end

    @testset "a Stripe that never answers ends in a ConnectionError, sent once" begin
        port, listener = Sockets.listenany(Sockets.localhost, 0)
        connections = Sockets.TCPSocket[]
        @async try
            while true
                push!(connections, Sockets.accept(listener))
            end
        catch
        end
        started = time()
        err = try
            SC.with_stripe(KEY; base_url = "http://127.0.0.1:$port", timeout = 1) do
                SC.create_refund(; payment_intent = "pi_1", idempotency_key = "refund-1")
            end
            nothing
        catch e
            e
        finally
            close(listener)
            foreach(close, connections)
        end
        @test err isa SC.ConnectionError
        @test time() - started < 10
        @test length(connections) == 1
    end

    @testset "a refused connection ends in a ConnectionError" begin
        port, listener = Sockets.listenany(Sockets.localhost, 0)
        close(listener)
        err = try
            SC.with_stripe(KEY; base_url = "http://127.0.0.1:$port") do
                SC.retrieve_account("acct_1")
            end
            nothing
        catch e
            e
        end
        @test err isa SC.ConnectionError
        @test occursin("could not connect", err.reason)
    end

    @testset "requests need a client" begin
        @test_throws ErrorException SC.retrieve_account("acct_1")
        @test_throws ErrorException SC.with_stripe(() -> SC.retrieve_account("acct_1"), "")
        @test SC.with_stripe(() -> 42, "") == 42
        # An empty key hides an outer client instead of falling back to it.
        @test_throws ErrorException SC.with_stripe(KEY) do
            SC.with_stripe(() -> SC.retrieve_account("acct_1"), "")
        end
    end

    @testset "webhook signatures" begin
        payload = """{"id": "evt_1", "object": "event", "type": "account.updated",
            "api_version": "2025-05-28.basil", "created": 1762900000, "livemode": false,
            "pending_webhooks": 1, "request": {"id": null, "idempotency_key": null},
            "account": "acct_1", "data": {"object": {"id": "acct_1", "charges_enabled": true}}}"""
        secret = "whsec_test"
        verify(signature; kw...) = SC.verify_webhook_signature(payload, signature, secret; kw...)
        @test verify(signed(payload))
        @test !verify(signed(payload; secret = "whsec_other"))
        @test !SC.verify_webhook_signature(payload * " ", signed(payload), secret)
        old = signed(payload; t = round(Int, time()) - 301)
        @test !verify(old)
        @test verify(old; tolerance = 600)
        # While a secret is being rolled, Stripe signs with each secret.
        rolled = signed(payload; secret = "whsec_old")
        @test verify(rolled * ",v1=" * last(split(signed(payload), "v1=")))
        @test verify(signed(payload) * ",v0=ignored")
        @test !verify(String(last(split(signed(payload), ','))))   # no timestamp
        @test !verify("t=soon," * last(split(signed(payload), ',')))
        @test !verify(String(first(split(signed(payload), ','))))  # no signature
        @test !verify("")

        event = SC.construct_webhook_event(payload, signed(payload), secret)
        @test event isa SC.WebhookEvent
        @test (event.id, event.type, event.account) == ("evt_1", "account.updated", "acct_1")
        @test event.data["object"]["charges_enabled"] === true
        @test event.livemode === false
        err = try SC.construct_webhook_event(payload, old, secret); nothing catch e; e end
        @test err isa SC.SignatureVerificationError
        @test occursin("Stripe-Signature", sprint(showerror, err))
    end

    @testset "Connect OAuth answers parse" begin
        token = JSON.parse("""{"access_token": "sk_test_x", "livemode": false, "refresh_token": "rt_x",
            "token_type": "bearer", "stripe_publishable_key": "pk_test_x", "stripe_user_id": "acct_9",
            "scope": "read_write"}""", SC.OAuthTokenResponse)
        @test (token.stripe_user_id, token.scope, token.livemode) == ("acct_9", "read_write", false)
    end
end
