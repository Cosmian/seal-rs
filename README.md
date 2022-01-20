# RUSTY SEAL

An (incomplete) Rust wrapper around SEAL 3.5.9. (and is unlikely to work with any other version)

- `seal`: native C++ library
- `seal/util`: tools used by native lib
- `seal/c`: C wrapper for convenience

https://github.com/microsoft/SEAL/tree/master/native/src/seal

## Building

We generate bindings for Rust using the C wrapper provided by SEAL, and located in `seal/c`

`build.rs` takes care of the rest.

## Updating

Run
``` sh
git subtree pull --prefix seal https://github.com/microsoft/SEAL.git ref --squash
```
where `ref` is the desired remote reference to use for the update.

## Thread safety

It seems that the Seal library is:
- thread safe for operations (add, rotate, mul, ...)
- **not** thread safe for object creation (Context, Encoder, Params, ...)

## Using

The best is to look at the test files, particularly the one building the table below.

## Speed Benchmarks
A few stats on what can be achieved with BFV

```
| -------- | ------------ | ------ | ------ | --------- | ------ | ------ | --------- | ------ |
| degree   | modulus      | bits   | m.p.   | µs/slot   | ms     | mul.   | µs/slot   | ms     |
| -------- | ------------ | ------ | ------ | --------- | ------ | ------ | --------- | ------ |
| 16384    | 3735553      | 22     | 12     | 1         | 26     | 8      | 8         | 134    |
| 32768    | 3735553      | 22     | 27     | 3         | 109    | 18     | 18        | 608    |
| -------- | ------------ | ------ | ------ | --------- | ------ | ------ | --------- | ------ |
| 16384    | 8257537      | 23     | 12     | 1         | 25     | 8      | 7         | 128    |
| 32768    | 8257537      | 23     | 26     | 3         | 111    | 18     | 18        | 621    |
| -------- | ------------ | ------ | ------ | --------- | ------ | ------ | --------- | ------ |
| 16384    | 16580609     | 24     | 11     | 1         | 25     | 8      | 7         | 124    |
| 32768    | 16580609     | 24     | 25     | 3         | 114    | 17     | 19        | 645    |
| -------- | ------------ | ------ | ------ | --------- | ------ | ------ | --------- | ------ |
| 16384    | 33292289     | 25     | 11     | 1         | 26     | 8      | 8         | 133    |
| 32768    | 33292289     | 25     | 24     | 3         | 114    | 17     | 19        | 633    |
| -------- | ------------ | ------ | ------ | --------- | ------ | ------ | --------- | ------ |
| 16384    | 67043329     | 26     | 10     | 1         | 26     | 7      | 7         | 130    |
| 32768    | 67043329     | 26     | 23     | 3         | 112    | 17     | 19        | 628    |
| -------- | ------------ | ------ | ------ | --------- | ------ | ------ | --------- | ------ |
| 16384    | 133857281    | 27     | 10     | 1         | 27     | 7      | 8         | 138    |
| 32768    | 132710401    | 27     | 23     | 3         | 109    | 16     | 18        | 613    |
| -------- | ------------ | ------ | ------ | --------- | ------ | ------ | --------- | ------ |
| 16384    | 268369921    | 28     | 10     | 1         | 26     | 7      | 7         | 130    |
| 32768    | 268369921    | 28     | 22     | 3         | 113    | 16     | 18        | 617    |
| -------- | ------------ | ------ | ------ | --------- | ------ | ------ | --------- | ------ |
| 16384    | 536641537    | 29     | 9      | 1         | 25     | 7      | 7         | 126    |
| 32768    | 536608769    | 29     | 21     | 3         | 108    | 15     | 18        | 606    |
| -------- | ------------ | ------ | ------ | --------- | ------ | ------ | --------- | ------ |
| 16384    | 2147352577   | 31     | 9      | 1         | 24     | 7      | 7         | 122    |
| 32768    | 2147352577   | 31     | 20     | 3         | 104    | 15     | 17        | 578    |
| -------- | ------------ | ------ | ------ | --------- | ------ | ------ | --------- | ------ |
```

`degree`: the polynomials degree - the higher, the bigger the ciphers, but more multiplications can be chained

`modulus`: a prime number which is the order of the field for the plain texts i.e. the maximum value, excluded, a plain text can have

`bits`: the number of bits of the plain texts (the modulus is calculated from that value and SEAL fails on 19 bits...)

`m.p.`: the multiplication depth plain text: the number of multiplications of a cipher text with a plain text that can be chained before it becomes impossible to correctly decrypt the result

`mul.`: the multiplication depth cipher text: the number of multiplications of a cipher text with another cipher text that can be chained before it becomes impossible to correctly decrypt the result

`µs/slot`: The time per batched scalar multiplication. in BFV, multiplications can be batched: the number of slots is equal to the degree of the polynomial -> for a  degree of 8192, 8192 scalar multiplications can be conducted in parallel on 8192 slots.

`ms`: the number of milliseconds to perform the multiplications on all the slots. The previous value is equal to this value divided by the number of slots

These benchmarks have been conducted on a single thread on an I7-8700  3.2 GHz

## Size Benchmarks

A `compact_size()`method is available on the `Evaluator` which will perform modulus switching to the maximum possible extent in order to reduce the size of the cipher texts.

The table below present the `noise` (budget) and `size`in kilobytes, before and after calling the method.
The sizes indicated are those after zip compression.


```
| ------- | ------- || ------- | ---------- || ------- | ---------- || ------ |
| deg. | bits |  | noise | size(kb) |  | noise | size(kb) |  | gain |
| ---- | ---- ||-------|----------||-------|----------||------|
|  8192 |    23 ||    29 |      417 ||    12 |      103 ||  76% |
| 16384 | 23  |  | 36 | 1822 |  | 17 | 225 |  | 88% |
| ----- | --- ||-------|----------||-------|----------||------|
|  8192 |    24 ||    23 |      417 ||    11 |      103 ||  76% |
| 16384 | 24  |  | 16 | 1822 |  | 15 | 225 |  | 88% |
| ----- | --- ||-------|----------||-------|----------||------|
|  8192 |    25 ||    19 |      417 ||    10 |      103 ||  76% |
| 16384 | 25  |  | 4 | 1822 |  | 4 | 226 |  | 88% |
| ----- | --- ||-------|----------||-------|----------||------|
|  8192 |    26 ||    20 |      417 ||     9 |      103 ||  76% |
| 16384 | 26  |  | 1 | 1822 |  | 1 | 225 |  | 88% |
| ----- | --- ||-------|----------||-------|----------||------|
|  8192 |    27 ||    15 |      417 ||     8 |      103 ||  76% |
| 16384 | 27  |  | 38 | 1822 |  | 13 | 225 |  | 88% |
| ----- | --- ||-------|----------||-------|----------||------|
|  8192 |    28 ||     6 |      417 ||     6 |      103 ||  76% |
| 16384 | 28  |  | 33 | 1822 |  | 12 | 226 |  | 88% |
| ----- | --- ||-------|----------||-------|----------||------|
|  8192 |    29 ||     6 |      417 ||     5 |      103 ||  76% |
| 16384 | 29  |  | 35 | 1822 |  | 11 | 225 |  | 88% |
| ----- | --- ||-------|----------||-------|----------||------|
```
