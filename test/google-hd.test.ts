import { describe, expect, it } from "vitest";
import { parseGoogleHdSetting, passesGoogleHd } from "../src/auth/google-hd.js";

describe("parseGoogleHdSetting", () => {
  it.each([
    [undefined, "off"],
    ["", "off"],
    ["false", "off"],
    ["true", "on"],
    ["TRUE", "invalid"],
    ["True", "invalid"],
    [" true", "invalid"],
    ["true ", "invalid"],
    ["1", "invalid"],
    ["yes", "invalid"],
    [true, "invalid"],
    [false, "invalid"],
    [null, "invalid"],
    [1, "invalid"],
  ])("reads %j as %s", (value, expected) => {
    expect(parseGoogleHdSetting(value)).toBe(expected);
  });
});

describe("passesGoogleHd", () => {
  it("accepts a gmail.com address without hd", () => {
    expect(passesGoogleHd("alice@gmail.com", {})).toBe(true);
    expect(passesGoogleHd("alice@gmail.com", { hd: "" })).toBe(true);
  });

  it("does not treat googlemail.com or a subdomain of gmail.com as Gmail", () => {
    expect(passesGoogleHd("alice@googlemail.com", {})).toBe(false);
    expect(passesGoogleHd("alice@mail.gmail.com", {})).toBe(false);
    expect(passesGoogleHd("alice@gmail.com.example.com", {})).toBe(false);
  });

  it("takes the domain after the last @", () => {
    expect(passesGoogleHd("alice@gmail.com@example.com", {})).toBe(false);
    expect(passesGoogleHd("alice@example.com@gmail.com", {})).toBe(true);
  });

  it("does not treat a string without @ as Gmail", () => {
    expect(passesGoogleHd("gmail.com", {})).toBe(false);
    expect(passesGoogleHd("gmail.com", { hd: "example.com" })).toBe(true);
  });

  it("relies on the caller to normalize the email", () => {
    expect(passesGoogleHd("alice@GMAIL.com", {})).toBe(false);
  });

  it("requires a non-blank string hd for other addresses", () => {
    expect(passesGoogleHd("alice@example.com", { hd: "example.com" })).toBe(true);
    expect(passesGoogleHd("alice@example.com", {})).toBe(false);
    expect(passesGoogleHd("alice@example.com", { hd: "" })).toBe(false);
    expect(passesGoogleHd("alice@example.com", { hd: "  " })).toBe(false);
    expect(passesGoogleHd("alice@example.com", { hd: true })).toBe(false);
    expect(passesGoogleHd("alice@example.com", { hd: ["example.com"] })).toBe(false);
    expect(passesGoogleHd("alice@example.com", { hd: null })).toBe(false);
  });

  it("does not compare hd with the domain of the email", () => {
    expect(passesGoogleHd("alice@example.com", { hd: "partner.example" })).toBe(true);
  });
});
