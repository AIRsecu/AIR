package com.shop.dto.tenant;

public record UpdateTenantRequest(String name, String slug, String domain,
                                  String description, String logoUrl, Boolean isActive) {}
