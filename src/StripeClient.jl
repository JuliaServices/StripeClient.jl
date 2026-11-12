"""
    StripeClient

Calls Stripe's REST API: Checkout Sessions, refunds, Connect accounts with their
onboarding, dashboard, and OAuth links, Stripe Tax for connected accounts, and
webhook signature checks. Answers parse into typed structs; fields a struct does
not declare are skipped.

Requests use the client that [`with_stripe`](@ref) sets for a block of code. Pass
`stripe_account` to act on a connected account (Stripe Connect direct charges).

The package compiles with `juliac --trim=safe`.
"""
module StripeClient

using HTTP, JSON, SHA, ScopedValues

"Stripe's API host."
const API_BASE_URL = "https://api.stripe.com"
"Stripe's Connect OAuth host."
const CONNECT_BASE_URL = "https://connect.stripe.com"
"""
The Stripe API version that tax locations and tax products are created with: the
first version that accepts their performance-location fields.
"""
const TAX_API_VERSION = "2025-05-28.basil"

# ══════════════════════════════════════════════════════════════════════════════
# Client
# ══════════════════════════════════════════════════════════════════════════════

# Stripe's own libraries wait 30 s to connect and 80 s for an answer. These calls
# usually run inside someone's web request, so they give up sooner: 10 s to
# connect and 30 s for the whole call. HTTP.jl never resends a request whose
# answer timed out.
const CONNECT_TIMEOUT_SECONDS = 10
const TIMEOUT_SECONDS = 30

struct Client
    api_key::String
    base_url::String
    "Seconds one call may take in all, HTTP.jl's retries included."
    timeout::Int
end

const STRIPE_CLIENT = ScopedValue{Client}()

"""
    with_stripe(f, api_key; base_url = API_BASE_URL, timeout = 30)

Run `f()` with a client for the secret key `api_key`; every request function
called inside `f` uses it. `timeout` caps the seconds one request may take in
all. With an empty `api_key`, `f` runs with no client, and any request in it
throws.

```julia
StripeClient.with_stripe(ENV["STRIPE_SECRET_KEY"]) do
    StripeClient.retrieve_account("acct_123")
end
```
"""
function with_stripe(f::F, api_key::String; base_url::String = API_BASE_URL,
                     timeout::Int = TIMEOUT_SECONDS) where {F}
    isempty(api_key) && return f()
    @with STRIPE_CLIENT => Client(api_key, base_url, timeout) f()
end

function _get_client()
    isassigned(STRIPE_CLIENT) || error("No Stripe client set. Use `with_stripe` to set credentials.")
    return STRIPE_CLIENT[]
end

# ══════════════════════════════════════════════════════════════════════════════
# Errors
# ══════════════════════════════════════════════════════════════════════════════

"""
    AuthenticationError(status, message)

Stripe refused the API key: an HTTP 401 (the key is wrong or revoked) or 403 (the
key may not use this endpoint or connected account). `message` is Stripe's
explanation.

It means the server's configuration is wrong, not that its user did anything
wrong, so a web server should not pass the 401 or 403 on to its own client.
"""
struct AuthenticationError <: Exception
    status::Int
    message::String
end

Base.showerror(io::IO, e::AuthenticationError) =
    print(io, "StripeClient.AuthenticationError (HTTP ", e.status, "): ", e.message)

"""
    ConnectionError(reason)

Stripe could not be reached, or did not answer within the client's timeout.
Trying again can succeed. A request that timed out may still have reached
Stripe, so send a retried POST with the same `idempotency_key`.
"""
struct ConnectionError <: Exception
    reason::String
end

Base.showerror(io::IO, e::ConnectionError) =
    print(io, "StripeClient.ConnectionError: ", e.reason)

"""
    SignatureVerificationError()

A webhook's `Stripe-Signature` header does not match its payload and the
endpoint secret, or its timestamp is outside the allowed age.
"""
struct SignatureVerificationError <: Exception end

Base.showerror(io::IO, ::SignatureVerificationError) = print(io,
    "StripeClient.SignatureVerificationError: the Stripe-Signature header does not ",
    "match the payload, or its timestamp is too old")

@defaults struct _ErrorDetail
    message::Union{String,Nothing} = nothing
end

@defaults struct _ErrorEnvelope
    error::Union{_ErrorDetail,Nothing} = nothing
end

# Stripe's `error.message` from a failed answer, or a line naming the status.
function _error_message(e::HTTP.StatusError)::String
    response = e.response
    raw = if response isa HTTP.Response
        body = response.body
        body isa String ? body :
            body isa Vector{UInt8} ? String(copy(body)) :
            body isa Base.CodeUnits{UInt8,String} ? String(body) :
            body isa HTTP.BytesBody{Vector{UInt8}} ? String(copy(body.data)) :
            body isa HTTP.BytesBody{Base.CodeUnits{UInt8,String}} ? String(body.data) : ""
    else
        ""
    end
    message = try
        parsed = JSON.parse(raw, _ErrorEnvelope)
        parsed.error === nothing ? nothing : parsed.error.message
    catch
        nothing
    end
    message isa String && !isempty(message) && return message
    return "Stripe rejected the request (HTTP $(e.status))"
end

"""
    permanent_request_error_message(e) -> Union{String,Nothing}

Stripe's message when `e` is a request Stripe refused outright: an HTTP 400
(invalid request), 402 (for example a declined card), or 404 (no such object).
Such a request fails the same way every time it is sent. Returns `nothing` for
anything worth retrying: network failures, timeouts, rate limits, and Stripe's
5xx answers.
"""
@noinline function permanent_request_error_message(@nospecialize(e))::Union{String,Nothing}
    e isa HTTP.StatusError || return nothing
    e.status in (400, 402, 404) || return nothing
    return _error_message(e)
end

@noinline function _throw_if_unavailable(@nospecialize(e))
    e isa HTTP.TimeoutError &&
        throw(ConnectionError("no answer in time ($(e.operation))"))
    e isa HTTP.ConnectError &&
        throw(ConnectionError("could not connect to $(e.address)"))
    e isa HTTP.DNSError &&
        throw(ConnectionError("could not look up $(e.hostname)"))
    return nothing
end

@noinline function _throw_if_auth_error(@nospecialize(e))
    e isa HTTP.StatusError || return nothing
    e.status == 401 || e.status == 403 || return nothing
    throw(AuthenticationError(Int(e.status), _error_message(e)))
end

# ══════════════════════════════════════════════════════════════════════════════
# Requests
# ══════════════════════════════════════════════════════════════════════════════

function _headers(client::Client; idempotency_key::Union{String,Nothing} = nothing,
                  stripe_account::Union{String,Nothing} = nothing,
                  stripe_version::Union{String,Nothing} = nothing)
    h = Dict(
        "Authorization" => "Bearer $(client.api_key)",
        "Content-Type" => "application/x-www-form-urlencoded"
    )
    idempotency_key !== nothing && (h["Idempotency-Key"] = idempotency_key)
    stripe_account !== nothing && (h["Stripe-Account"] = stripe_account)
    stripe_version !== nothing && (h["Stripe-Version"] = stripe_version)
    return h
end

"""
    form_params(params::Dict{Symbol,Any}) -> Vector{Pair{String,String}}

The form fields Stripe reads for `params`, in its bracket notation: a nested
dictionary `Dict(:a => Dict(:b => 1))` becomes `"a[b]" => "1"`, a `Vector{String}`
becomes repeated `"key[]"` fields, and other vectors become indexed `"key[0]"`,
`"key[1]"` fields. `nothing` values are left out.

Values may be `String`, `Symbol`, `Int`, `Bool`, `Float64`, `Dict{Symbol,Any}`,
`Dict{String,String}`, `Dict{Symbol,String}`, `Dict{Symbol,Int}`,
`Vector{String}`, `Vector{Dict{Symbol,Any}}`, or `Vector{Any}`. Any other type
throws an `ArgumentError`.
"""
form_params(params::Dict{Symbol,Any}) = _to_form_params(params, "")

# One method or branch per value type, so `juliac --trim` can check every call.
function _to_form_params(data::Dict{Symbol,Any}, prefix::String)
    params = Pair{String,String}[]
    for (k, v) in data
        key = isempty(prefix) ? string(k) : "$(prefix)[$(k)]"
        _append_form_value!(params, key, v)
    end
    return params
end

function _to_form_params(data::Dict{String,String}, prefix::String)
    params = Pair{String,String}[]
    for (k, v) in data
        key = isempty(prefix) ? k : "$(prefix)[$(k)]"
        push!(params, key => v)
    end
    return params
end

function _append_form_value!(params::Vector{Pair{String,String}}, key::String, @nospecialize(v))
    if v isa Dict{Symbol,Any}
        append!(params, _to_form_params(v, key))
    elseif v isa Dict{String,String}
        append!(params, _to_form_params(v, key))
    elseif v isa Dict{Symbol,String}
        for (k, item) in v
            push!(params, "$(key)[$(k)]" => item)
        end
    elseif v isa Dict{Symbol,Int}
        for (k, item) in v
            push!(params, "$(key)[$(k)]" => string(item))
        end
    elseif v isa Vector{Dict{Symbol,Any}}
        for (i, item) in enumerate(v)
            append!(params, _to_form_params(item, "$(key)[$(i-1)]"))
        end
    elseif v isa Vector{String}
        # Stripe reads `key[]=a&key[]=b` as an array. A bare repeated key reads
        # as a string, which Stripe refuses with "Invalid array" (e.g. `expand`).
        for item in v
            push!(params, "$(key)[]" => item)
        end
    elseif v isa Vector{Any}
        # Every element gets an index: Stripe refuses one key that mixes `key[]`
        # with `key[i][...]`, so a vector of strings and dictionaries needs both
        # kinds indexed.
        for (i, item) in enumerate(v)
            if item isa Dict{Symbol,Any}
                append!(params, _to_form_params(item, "$(key)[$(i-1)]"))
            else
                push!(params, "$(key)[$(i-1)]" => _form_string(item))
            end
        end
    elseif v !== nothing
        push!(params, key => _form_string(v))
    end
    return params
end

@noinline _form_string(@nospecialize(x))::String =
    x isa String ? x :
    x isa Symbol ? String(x) :
    x isa Int ? string(x) :
    x isa Bool ? string(x) :
    x isa Float64 ? string(x) :
    throw(ArgumentError("unsupported form parameter value type: $(typeof(x))"))

_upper_hex_nibble(n::UInt8)::UInt8 = n < 0x0a ? UInt8('0') + n : UInt8('A') + (n - 0x0a)

# Percent-encodes every byte outside RFC 3986's unreserved characters. HTTP's
# escapeuri is not used here because `juliac --trim` cannot check its internals.
function _uri_encode(s::String)::String
    io = IOBuffer()
    for b in codeunits(s)
        if (UInt8('A') <= b <= UInt8('Z')) || (UInt8('a') <= b <= UInt8('z')) ||
           (UInt8('0') <= b <= UInt8('9')) ||
           b == UInt8('-') || b == UInt8('.') || b == UInt8('_') || b == UInt8('~')
            write(io, b)
        else
            write(io, UInt8('%'))
            write(io, _upper_hex_nibble(b >> 4))
            write(io, _upper_hex_nibble(b & 0x0f))
        end
    end
    return String(take!(io))
end

_form_encode(pairs::Vector{Pair{String,String}}) =
    join([string(_uri_encode(k), "=", _uri_encode(v)) for (k, v) in pairs], "&")

# Turns the HTTP errors that mean "Stripe refused the key" or "Stripe did not
# answer" into AuthenticationError and ConnectionError; other errors propagate.
function _send(method::String, url::String, headers, body::Union{String,Nothing}, timeout::Int)
    try
        body === nothing && return HTTP.request(method, url, headers;
            connect_timeout = CONNECT_TIMEOUT_SECONDS, request_timeout = timeout)
        return HTTP.request(method, url, headers; body,
            connect_timeout = CONNECT_TIMEOUT_SECONDS, request_timeout = timeout)
    catch e
        _throw_if_auth_error(e)
        _throw_if_unavailable(e)
        rethrow()
    end
end

function _make_request(::Type{T}, client::Client, method::String, path::String;
                       body::Union{Dict{Symbol,Any},Nothing} = nothing,
                       query::Union{Dict{Symbol,Any},Nothing} = nothing,
                       idempotency_key::Union{String,Nothing} = nothing,
                       stripe_account::Union{String,Nothing} = nothing,
                       stripe_version::Union{String,Nothing} = nothing) where {T}
    url = string(client.base_url, "/", path)
    headers = _headers(client; idempotency_key, stripe_account, stripe_version)
    if query !== nothing && !isempty(query)
        url = string(url, "?", _form_encode(form_params(query)))
    end
    body_str = body === nothing ? nothing : _form_encode(form_params(body))
    response = _send(method, url, headers, body_str, client.timeout)
    return JSON.parse(String(response.body), T)
end

# ══════════════════════════════════════════════════════════════════════════════
# Response types
# ══════════════════════════════════════════════════════════════════════════════

"One page of a Stripe list. Pass the last item's `id` as `starting_after` for the next page."
@defaults struct ListResponse{T}
    data::Vector{T}
    object::String = "list"
    has_more::Bool = false
    url::Union{String,Nothing} = nothing
end

"A Stripe Product, as [`create_tax_product`](@ref) returns it."
@defaults struct Product
    id::String
    name::String
    object::String = "product"
    active::Bool = true
    description::Union{String,Nothing} = nothing
    default_price::Union{String,Nothing} = nothing
    images::Union{Vector{String},Nothing} = nothing
    metadata::Union{Dict{String,String},Nothing} = nothing
    type::Union{String,Nothing} = nothing
    created::Union{Int,Nothing} = nothing
    updated::Union{Int,Nothing} = nothing
    livemode::Union{Bool,Nothing} = nothing
    url::Union{String,Nothing} = nothing
    unit_label::Union{String,Nothing} = nothing
    statement_descriptor::Union{String,Nothing} = nothing
    shippable::Union{Bool,Nothing} = nothing
    tax_code::Union{String,Nothing} = nothing
end

@defaults struct CheckoutAutomaticTax
    enabled::Bool = false
    status::Union{String,Nothing} = nothing
    liability::Union{Dict{String,Any},Nothing} = nothing
end

@defaults struct CheckoutTaxRateBreakdown
    display_name::Union{String,Nothing} = nothing
    effective_percentage::Union{Float64,Nothing} = nothing
    percentage::Union{Float64,Nothing} = nothing
    jurisdiction::Union{String,Nothing} = nothing
    jurisdiction_level::Union{String,Nothing} = nothing
    state::Union{String,Nothing} = nothing
    country::Union{String,Nothing} = nothing
    tax_type::Union{String,Nothing} = nothing
end

@defaults struct CheckoutTaxBreakdownItem
    amount::Int = 0
    taxable_amount::Union{Int,Nothing} = nothing
    rate::CheckoutTaxRateBreakdown = CheckoutTaxRateBreakdown()
end

@defaults struct CheckoutTotalBreakdown
    taxes::Vector{CheckoutTaxBreakdownItem} = CheckoutTaxBreakdownItem[]
end

@defaults struct CheckoutTotalDetails
    amount_discount::Int = 0
    amount_shipping::Union{Int,Nothing} = nothing
    amount_tax::Int = 0
    "Present only when the request expands `total_details.breakdown`."
    breakdown::Union{CheckoutTotalBreakdown,Nothing} = nothing
end

"A Checkout Session. Amounts are in the currency's smallest unit, such as cents."
@defaults struct CheckoutSession
    id::String
    mode::String
    object::String = "checkout.session"
    status::Union{String,Nothing} = nothing
    payment_status::Union{String,Nothing} = nothing
    url::Union{String,Nothing} = nothing
    success_url::Union{String,Nothing} = nothing
    cancel_url::Union{String,Nothing} = nothing
    client_reference_id::Union{String,Nothing} = nothing
    customer::Union{String,Nothing} = nothing
    customer_email::Union{String,Nothing} = nothing
    customer_creation::Union{String,Nothing} = nothing
    amount_subtotal::Union{Int,Nothing} = nothing
    amount_total::Union{Int,Nothing} = nothing
    currency::Union{String,Nothing} = nothing
    payment_intent::Union{String,Nothing} = nothing
    subscription::Union{String,Nothing} = nothing
    metadata::Union{Dict{String,String},Nothing} = nothing
    created::Union{Int,Nothing} = nothing
    expires_at::Union{Int,Nothing} = nothing
    livemode::Union{Bool,Nothing} = nothing
    allow_promotion_codes::Union{Bool,Nothing} = nothing
    automatic_tax::Union{CheckoutAutomaticTax,Nothing} = nothing
    total_details::Union{CheckoutTotalDetails,Nothing} = nothing
end

"A refund. `status` is `pending`, `requires_action`, `succeeded`, `failed`, or `canceled`."
@defaults struct Refund
    id::String
    object::String = "refund"
    amount::Union{Int,Nothing} = nothing
    currency::Union{String,Nothing} = nothing
    payment_intent::Union{String,Nothing} = nothing
    charge::Union{String,Nothing} = nothing
    status::Union{String,Nothing} = nothing
    failure_reason::Union{String,Nothing} = nothing
    reason::Union{String,Nothing} = nothing
    created::Union{Int,Nothing} = nothing
    metadata::Union{Dict{String,String},Nothing} = nothing
end

"""
A connected account. Nested objects such as `business_profile` and `settings`
are not kept; each optional nested struct adds code that `juliac --trim` must
check, so add one when a caller needs it.
"""
@defaults struct Account
    id::String
    object::String = "account"
    type::Union{String,Nothing} = nothing
    business_type::Union{String,Nothing} = nothing
    charges_enabled::Union{Bool,Nothing} = nothing
    country::Union{String,Nothing} = nothing
    created::Union{Int,Nothing} = nothing
    default_currency::Union{String,Nothing} = nothing
    details_submitted::Union{Bool,Nothing} = nothing
    email::Union{String,Nothing} = nothing
    metadata::Union{Dict{String,String},Nothing} = nothing
    payouts_enabled::Union{Bool,Nothing} = nothing
    "Values vary in type (lists, numbers, strings, `nothing`); check each one's type before use."
    requirements::Dict{String,Any} = Dict{String,Any}()
end

"A one-time link that sends a connected account's owner through Stripe's onboarding."
@defaults struct AccountLink
    url::String
    object::String = "account_link"
    created::Union{Int,Nothing} = nothing
    expires_at::Union{Int,Nothing} = nothing
end

"A one-time link into an Express or Custom account's Stripe dashboard."
@defaults struct LoginLink
    url::String
    object::String = "login_link"
    created::Union{Int,Nothing} = nothing
end

"The answer to a Connect OAuth code exchange. `stripe_user_id` is the linked account's id."
@defaults struct OAuthTokenResponse
    stripe_user_id::String
    livemode::Union{Bool,Nothing} = nothing
    scope::Union{String,Nothing} = nothing
end

"A short-lived session for Stripe's embedded Connect components. Hand `client_secret` only to the account's owner."
@defaults struct AccountSession
    account::String
    client_secret::String
    expires_at::Int
    object::String = "account_session"
    livemode::Bool = false
end

@defaults struct TaxSettingsPendingDetails
    missing_fields::Union{Vector{String},Nothing} = nothing
end

@defaults struct TaxSettingsStatusDetails
    pending::Union{TaxSettingsPendingDetails,Nothing} = nothing
end

"An account's Stripe Tax settings. `status` is `active` or `pending`."
@defaults struct TaxSettings
    object::String = "tax.settings"
    status::String = "pending"
    status_details::Union{TaxSettingsStatusDetails,Nothing} = nothing
    defaults::Union{Dict{String,Any},Nothing} = nothing
    head_office::Union{Dict{String,Any},Nothing} = nothing
    livemode::Bool = false
end

@defaults struct TaxRegistrationUSOptions
    state::Union{String,Nothing} = nothing
    type::Union{String,Nothing} = nothing
end

@defaults struct TaxRegistrationCountryOptions
    us::Union{TaxRegistrationUSOptions,Nothing} = nothing
end

"Where an account is registered to collect tax."
@defaults struct TaxRegistration
    id::String
    country::String
    status::String
    object::String = "tax.registration"
    country_options::Union{TaxRegistrationCountryOptions,Nothing} = nothing
    active_from::Union{Int,Nothing} = nothing
    expires_at::Union{Int,Nothing} = nothing
    livemode::Bool = false
end

"A place where a taxable service is performed, such as an event venue."
@defaults struct TaxLocation
    id::String
    object::String = "tax.location"
    display_name::Union{String,Nothing} = nothing
    address::Union{Dict{String,Any},Nothing} = nothing
    livemode::Bool = false
end

"""
A webhook event. `data["object"]` holds the object the event is about, as parsed
JSON. `account` is set for events from connected accounts.
"""
@defaults struct WebhookEvent
    id::String
    type::String
    object::String = "event"
    api_version::Union{String,Nothing} = nothing
    created::Union{Int,Nothing} = nothing
    data::Union{Dict{String,Any},Nothing} = nothing
    livemode::Union{Bool,Nothing} = nothing
    pending_webhooks::Union{Int,Nothing} = nothing
    request::Union{Dict{String,Any},Nothing} = nothing
    account::Union{String,Nothing} = nothing
end

# ══════════════════════════════════════════════════════════════════════════════
# Checkout Sessions
# ══════════════════════════════════════════════════════════════════════════════

"""
    create_checkout_session(params; stripe_account = nothing, idempotency_key = nothing) -> CheckoutSession

Create a Checkout Session from `params`, Stripe's create parameters as a
`Dict{Symbol,Any}` (see [`form_params`](@ref) for the value types it takes).
`params` needs `:mode` and `:success_url`.

```julia
StripeClient.create_checkout_session(Dict{Symbol,Any}(
    :mode => "payment",
    :success_url => "https://example.com/paid",
    :line_items => [Dict{Symbol,Any}(:quantity => 1, :price_data => Dict{Symbol,Any}(
        :currency => "usd", :unit_amount => 2500,
        :product_data => Dict{Symbol,Any}(:name => "Entry fee")))],
); idempotency_key = "order-42")
```
"""
function create_checkout_session(params::Dict{Symbol,Any};
                                 stripe_account::Union{String,Nothing} = nothing,
                                 idempotency_key::Union{String,Nothing} = nothing)::CheckoutSession
    return _make_request(CheckoutSession, _get_client(), "POST", "v1/checkout/sessions";
                         body = params, idempotency_key, stripe_account)
end

"""
    retrieve_checkout_session(id; expand = String[], stripe_account = nothing) -> CheckoutSession

Fetch a Checkout Session. `expand` names fields to include in full, such as
`"total_details.breakdown"`.
"""
function retrieve_checkout_session(id::String; expand::Vector{String} = String[],
                                   stripe_account::Union{String,Nothing} = nothing)::CheckoutSession
    query = isempty(expand) ? nothing : Dict{Symbol,Any}(:expand => expand)
    return _make_request(CheckoutSession, _get_client(), "GET", "v1/checkout/sessions/$id";
                         query, stripe_account)
end

"""
    expire_checkout_session(id; stripe_account = nothing) -> CheckoutSession

Close an `open` Checkout Session so it can no longer be paid.
"""
function expire_checkout_session(id::String;
                                 stripe_account::Union{String,Nothing} = nothing)::CheckoutSession
    return _make_request(CheckoutSession, _get_client(), "POST", "v1/checkout/sessions/$id/expire";
                         stripe_account)
end

# ══════════════════════════════════════════════════════════════════════════════
# Refunds
# ══════════════════════════════════════════════════════════════════════════════

"""
    create_refund(; payment_intent, amount = nothing, stripe_account = nothing,
                  idempotency_key = nothing, refund_application_fee = false) -> Refund

Refund a PaymentIntent in full (`amount = nothing`) or in part (`amount` in the
smallest currency unit). For a direct charge, pass the connected account as
`stripe_account`. `refund_application_fee = true` also returns the platform's
application fee to the connected account, in proportion for a partial refund.
"""
function create_refund(; payment_intent::String, amount::Union{Int,Nothing} = nothing,
                       stripe_account::Union{String,Nothing} = nothing,
                       idempotency_key::Union{String,Nothing} = nothing,
                       refund_application_fee::Bool = false)::Refund
    body = Dict{Symbol,Any}(:payment_intent => payment_intent)
    amount !== nothing && (body[:amount] = amount)
    refund_application_fee && (body[:refund_application_fee] = true)
    return _make_request(Refund, _get_client(), "POST", "v1/refunds";
                         body, idempotency_key, stripe_account)
end

"""
    retrieve_refund(id; stripe_account = nothing) -> Refund

Fetch a refund, for example to learn how a `pending` one ended when its webhook
never arrived.
"""
function retrieve_refund(id::String; stripe_account::Union{String,Nothing} = nothing)::Refund
    return _make_request(Refund, _get_client(), "GET", "v1/refunds/$id"; stripe_account)
end

"""
    list_refunds(; payment_intent, stripe_account = nothing, limit = 100,
                 starting_after = nothing) -> ListResponse{Refund}

One page of a PaymentIntent's refunds, newest first, on the account that owns
the charge.
"""
function list_refunds(; payment_intent::String,
                      stripe_account::Union{String,Nothing} = nothing,
                      limit::Int = 100,
                      starting_after::Union{String,Nothing} = nothing)::ListResponse{Refund}
    query = Dict{Symbol,Any}(:payment_intent => payment_intent, :limit => limit)
    starting_after !== nothing && (query[:starting_after] = starting_after)
    return _make_request(ListResponse{Refund}, _get_client(), "GET", "v1/refunds";
                         query, stripe_account)
end

"""
    refunded_total(payment_intent; stripe_account = nothing) -> Int

The sum of a PaymentIntent's `succeeded` refunds, across every page.
"""
function refunded_total(payment_intent::String;
                        stripe_account::Union{String,Nothing} = nothing)::Int
    total = 0
    cursor = nothing
    while true
        page = list_refunds(; payment_intent, stripe_account, limit = 100,
                            starting_after = cursor)
        for refund in page.data
            lowercase(something(refund.status, "")) == "succeeded" || continue
            total += something(refund.amount, 0)
        end
        page.has_more || return total
        isempty(page.data) && error("Stripe refund pagination returned has_more without data")
        cursor = last(page.data).id
    end
end

# ══════════════════════════════════════════════════════════════════════════════
# Connect accounts
# ══════════════════════════════════════════════════════════════════════════════

"""
    create_account(params) -> Account

Create a connected account from Stripe's create parameters as a
`Dict{Symbol,Any}`. Send its owner through onboarding with
[`create_account_link`](@ref).

```julia
StripeClient.create_account(Dict{Symbol,Any}(
    :type => "express",
    :capabilities => Dict{Symbol,Any}(
        :card_payments => Dict{Symbol,Any}(:requested => true),
        :transfers => Dict{Symbol,Any}(:requested => true))))
```
"""
function create_account(params::Dict{Symbol,Any})::Account
    return _make_request(Account, _get_client(), "POST", "v1/accounts"; body = params)
end

"""
    retrieve_account(id) -> Account

Fetch a connected account. After onboarding, check `details_submitted` and
`charges_enabled`.
"""
function retrieve_account(id::String)::Account
    return _make_request(Account, _get_client(), "GET", "v1/accounts/$id")
end

"""
    create_account_link(; account, refresh_url, return_url, type) -> AccountLink

A one-time link that sends `account`'s owner through Stripe's onboarding (`type =
"account_onboarding"`) or details update (`"account_update"`). Stripe sends them
to `return_url` when they finish, and to `refresh_url` when the link has expired
or was already used, where the app should make a new link.
"""
function create_account_link(; account::String, refresh_url::String, return_url::String,
                             type::String)::AccountLink
    body = Dict{Symbol,Any}(
        :account => account,
        :refresh_url => refresh_url,
        :return_url => return_url,
        :type => type
    )
    return _make_request(AccountLink, _get_client(), "POST", "v1/account_links"; body)
end

"""
    create_login_link(account_id) -> LoginLink

A one-time link into an Express or Custom account's Stripe dashboard.
"""
function create_login_link(account_id::String)::LoginLink
    return _make_request(LoginLink, _get_client(), "POST", "v1/accounts/$account_id/login_links")
end

"""
    oauth_token(code) -> OAuthTokenResponse

Exchange the Connect OAuth `code` that Stripe adds to the redirect after an
account's owner approves the platform for the id of their existing account. The
request goes to [`CONNECT_BASE_URL`](@ref). An invalid or used `code` throws
`HTTP.StatusError` 400.
"""
function oauth_token(code::String)::OAuthTokenResponse
    client = _get_client()
    headers = ["Authorization" => "Bearer $(client.api_key)",
               "Content-Type" => "application/x-www-form-urlencoded"]
    body = "grant_type=authorization_code&code=" * _uri_encode(code)
    response = _send("POST", CONNECT_BASE_URL * "/oauth/token", headers, body, client.timeout)
    return JSON.parse(String(response.body), OAuthTokenResponse)
end

# ══════════════════════════════════════════════════════════════════════════════
# Stripe Tax for connected accounts
# ══════════════════════════════════════════════════════════════════════════════

"""
    create_tax_account_session(account_id) -> AccountSession

A short-lived session for Stripe's embedded tax settings and tax registrations
components, for one connected account.
"""
function create_tax_account_session(account_id::String)::AccountSession
    body = Dict{Symbol,Any}(
        :account => account_id,
        :components => Dict{Symbol,Any}(
            :tax_settings => Dict{Symbol,Any}(:enabled => true),
            :tax_registrations => Dict{Symbol,Any}(:enabled => true),
        ),
    )
    return _make_request(AccountSession, _get_client(), "POST", "v1/account_sessions"; body)
end

"""
    retrieve_tax_settings(stripe_account) -> TaxSettings

A connected account's Stripe Tax settings.
"""
function retrieve_tax_settings(stripe_account::String)::TaxSettings
    return _make_request(TaxSettings, _get_client(), "GET", "v1/tax/settings"; stripe_account)
end

"""
    list_tax_registrations(stripe_account) -> ListResponse{TaxRegistration}

The first page of a connected account's tax registrations.
"""
function list_tax_registrations(stripe_account::String)::ListResponse{TaxRegistration}
    return _make_request(ListResponse{TaxRegistration}, _get_client(), "GET",
                         "v1/tax/registrations"; stripe_account)
end

"""
    create_tax_location(stripe_account, display_name, address; idempotency_key = nothing) -> TaxLocation

Create a performance location (where a taxable service such as an event takes
place) on a connected account. `address` holds Stripe's address fields, such as
`:line1`, `:city`, `:state`, `:postal_code`, and `:country`.
"""
function create_tax_location(stripe_account::String, display_name::String,
                             address::Dict{Symbol,Any};
                             idempotency_key::Union{String,Nothing} = nothing)::TaxLocation
    return _make_request(TaxLocation, _get_client(), "POST", "v1/tax/locations";
        body = Dict{Symbol,Any}(:display_name => display_name, :address => address),
        idempotency_key, stripe_account, stripe_version = TAX_API_VERSION)
end

"""
    create_tax_product(stripe_account, name, tax_code, tax_location_id;
                       metadata = Dict{String,String}(), idempotency_key = nothing) -> Product

Create a Product on a connected account whose tax is figured from `tax_code` at
the performance location `tax_location_id`. Use it in a direct charge on the same
account.
"""
function create_tax_product(stripe_account::String, name::String, tax_code::String,
                            tax_location_id::String;
                            metadata::Dict{String,String} = Dict{String,String}(),
                            idempotency_key::Union{String,Nothing} = nothing)::Product
    return _make_request(Product, _get_client(), "POST", "v1/products";
        body = Dict{Symbol,Any}(
            :name => name,
            :metadata => metadata,
            :tax_details => Dict{Symbol,Any}(
                :tax_code => tax_code,
                :tax_location => tax_location_id,
            ),
        ),
        idempotency_key, stripe_account, stripe_version = TAX_API_VERSION)
end

# ══════════════════════════════════════════════════════════════════════════════
# Webhooks
# ══════════════════════════════════════════════════════════════════════════════

"""
    verify_webhook_signature(payload, signature, secret; tolerance = 300) -> Bool

Whether `signature`, the request's `Stripe-Signature` header, signs the raw
request body `payload` with the endpoint secret `secret` (`whsec_...`), with a
timestamp at most `tolerance` seconds from now. While a secret is being rolled,
Stripe sends one `v1` signature per secret; any one of them may match.
"""
function verify_webhook_signature(payload::String, signature::String, secret::String;
                                  tolerance::Int = 300)::Bool
    timestamp = ""
    signatures = String[]
    for part in split(signature, ',')
        kv = split(strip(part), '=', limit = 2)
        length(kv) == 2 || continue
        kv[1] == "t" && (timestamp = String(kv[2]))
        kv[1] == "v1" && push!(signatures, String(kv[2]))
    end
    seconds = tryparse(Int, timestamp)
    seconds === nothing && return false
    abs(round(Int, time()) - seconds) > tolerance && return false
    expected = bytes2hex(hmac_sha256(Vector{UInt8}(secret), "$timestamp.$payload"))
    return any(s -> _secure_compare(expected, s), signatures)
end

"""
    construct_webhook_event(payload, signature, secret; tolerance = 300) -> WebhookEvent

Check the signature as [`verify_webhook_signature`](@ref) does, then parse
`payload`. Throws [`SignatureVerificationError`](@ref) when the check fails.

```julia
event = StripeClient.construct_webhook_event(String(req.body),
    HTTP.header(req, "Stripe-Signature"), ENV["STRIPE_WEBHOOK_SECRET"])
event.type == "account.updated" && handle(event.data["object"])
```
"""
function construct_webhook_event(payload::String, signature::String, secret::String;
                                 tolerance::Int = 300)::WebhookEvent
    verify_webhook_signature(payload, signature, secret; tolerance) ||
        throw(SignatureVerificationError())
    return JSON.parse(payload, WebhookEvent)
end

# Compares in time that does not depend on where the strings differ.
function _secure_compare(a::String, b::String)
    length(a) != length(b) && return false
    result = 0
    for (x, y) in zip(codeunits(a), codeunits(b))
        result |= xor(x, y)
    end
    return result == 0
end

end # module StripeClient
