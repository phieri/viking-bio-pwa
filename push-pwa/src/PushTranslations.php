<?php

/* Copyright (C) 2026 Philip Eriksson. All rights reserved. */

declare(strict_types=1);

namespace VikingBioPush;

final class PushTranslations
{
    private const string DEFAULT_LANGUAGE = 'en';

    private const array SUPPORTED_LANGUAGES = [
        'en' => 'English',
        'sv' => 'Svenska',
        'no' => 'Norsk',
        'fi' => 'Suomi',
        'da' => 'Dansk',
        'is' => 'Íslenska',
    ];

    private const array MESSAGES = [
        'en' => [
            'test.title' => 'Test notification',
            'test.body' => 'This is a Viking Bio test alert from the push PWA.',
            'cleaning.title' => 'Weekly cleaning reminder',
            'cleaning.body' => 'Time for your weekly burner cleaning reminder.',
            'alert.default.title' => 'Viking Bio alert',
            'alert.default.body' => 'New burner status update received.',
            'flame.on.title' => 'Burner started',
            'flame.on.body' => 'Flame detected on {device}.',
            'flame.off.title' => 'Burner stopped',
            'flame.off.body' => 'Flame cleared on {device}.',
            'flame.default.body' => 'Flame state changed on {device}.',
            'error.stale.title' => 'Telemetry lost',
            'error.stale.body' => 'No fresh telemetry received from {device}.',
            'error.code.title' => 'Burner error',
            'error.code.body' => 'Device {device} reported error code {error}.',
            'error.default.title' => 'Burner alert',
            'error.default.body' => 'Device {device} reported an error state.',
            'heartbeat.title' => 'Burner heartbeat',
            'heartbeat.body' => 'No alert activity has been reported by {device} in the last 24 hours.',
            'suffix.temperature' => ' Temperature {temp}°C.',
            'suffix.lfs.healthy' => ' LittleFS healthy.',
            'suffix.lfs.degraded' => ' LittleFS degraded.',
        ],
        'sv' => [
            'test.title' => 'Testnotifiering', 'test.body' => 'Detta är en Viking Bio-testvarning från push-PWA:n.',
            'cleaning.title' => 'Veckovis rengöringspåminnelse', 'cleaning.body' => 'Dags för din veckovisa rengöring av brännaren.',
            'alert.default.title' => 'Viking Bio-varning', 'alert.default.body' => 'Ny statusuppdatering från brännaren har tagits emot.',
            'flame.on.title' => 'Brännaren startade', 'flame.on.body' => 'Flamma upptäcktes på {device}.',
            'flame.off.title' => 'Brännaren stoppade', 'flame.off.body' => 'Flamman slocknade på {device}.', 'flame.default.body' => 'Flamstatus ändrades på {device}.',
            'error.stale.title' => 'Telemetri saknas', 'error.stale.body' => 'Ingen färsk telemetri togs emot från {device}.',
            'error.code.title' => 'Brännarfel', 'error.code.body' => 'Enheten {device} rapporterade felkod {error}.',
            'error.default.title' => 'Brännarvarning', 'error.default.body' => 'Enheten {device} rapporterade ett felläge.',
            'heartbeat.title' => 'Brännar-heartbeat', 'heartbeat.body' => 'Ingen varningsaktivitet har rapporterats av {device} under de senaste 24 timmarna.',
            'suffix.temperature' => ' Temperatur {temp}°C.', 'suffix.lfs.healthy' => ' LittleFS är frisk.', 'suffix.lfs.degraded' => ' LittleFS är degraderat.',
        ],
        'no' => [
            'test.title' => 'Testvarsel', 'test.body' => 'Dette er et Viking Bio-testvarsel fra push-PWA-en.',
            'cleaning.title' => 'Ukentlig rengjøringspåminnelse', 'cleaning.body' => 'Det er tid for den ukentlige rengjøringen av brenneren.',
            'alert.default.title' => 'Viking Bio-varsel', 'alert.default.body' => 'Ny statusoppdatering fra brenneren er mottatt.',
            'flame.on.title' => 'Brenneren startet', 'flame.on.body' => 'Flamme oppdaget på {device}.',
            'flame.off.title' => 'Brenneren stoppet', 'flame.off.body' => 'Flammen forsvant på {device}.', 'flame.default.body' => 'Flammetilstanden endret seg på {device}.',
            'error.stale.title' => 'Telemetri tapt', 'error.stale.body' => 'Ingen fersk telemetri ble mottatt fra {device}.',
            'error.code.title' => 'Brennerfeil', 'error.code.body' => 'Enheten {device} rapporterte feilkode {error}.',
            'error.default.title' => 'Brennervarsel', 'error.default.body' => 'Enheten {device} rapporterte en feiltilstand.',
            'heartbeat.title' => 'Heartbeat fra brenner', 'heartbeat.body' => 'Ingen varselaktivitet er rapportert fra {device} de siste 24 timene.',
            'suffix.temperature' => ' Temperatur {temp}°C.', 'suffix.lfs.healthy' => ' LittleFS er frisk.', 'suffix.lfs.degraded' => ' LittleFS er degradert.',
        ],
        'fi' => [
            'test.title' => 'Testi-ilmoitus', 'test.body' => 'Tämä on Viking Bion testihälytys push-PWA:sta.',
            'cleaning.title' => 'Viikoittainen puhdistusmuistutus', 'cleaning.body' => 'On aika tehdä polttimen viikoittainen puhdistus.',
            'alert.default.title' => 'Viking Bio -hälytys', 'alert.default.body' => 'Polttimelta saatiin uusi tilapäivitys.',
            'flame.on.title' => 'Poltin käynnistyi', 'flame.on.body' => 'Liekki havaittiin laitteessa {device}.',
            'flame.off.title' => 'Poltin pysähtyi', 'flame.off.body' => 'Liekki sammui laitteessa {device}.', 'flame.default.body' => 'Liekin tila muuttui laitteessa {device}.',
            'error.stale.title' => 'Telemetria katkesi', 'error.stale.body' => 'Laitteelta {device} ei saatu uutta telemetriaa.',
            'error.code.title' => 'Polttimen virhe', 'error.code.body' => 'Laite {device} ilmoitti virhekoodin {error}.',
            'error.default.title' => 'Polttimen hälytys', 'error.default.body' => 'Laite {device} ilmoitti virhetilasta.',
            'heartbeat.title' => 'Polttimen heartbeat', 'heartbeat.body' => 'Laite {device} ei ole raportoinut hälytystoimintaa viimeisen 24 tunnin aikana.',
            'suffix.temperature' => ' Lämpötila {temp}°C.', 'suffix.lfs.healthy' => ' LittleFS on kunnossa.', 'suffix.lfs.degraded' => ' LittleFS on heikentynyt.',
        ],
        'da' => [
            'test.title' => 'Testnotifikation', 'test.body' => 'Dette er en Viking Bio-testadvarsel fra push-PWAen.',
            'cleaning.title' => 'Ugentlig rengøringspåmindelse', 'cleaning.body' => 'Det er tid til den ugentlige rengøring af brænderen.',
            'alert.default.title' => 'Viking Bio-advarsel', 'alert.default.body' => 'Der er modtaget en ny statusopdatering fra brænderen.',
            'flame.on.title' => 'Brænderen startede', 'flame.on.body' => 'Flamme registreret på {device}.',
            'flame.off.title' => 'Brænderen stoppede', 'flame.off.body' => 'Flammen forsvandt på {device}.', 'flame.default.body' => 'Flammetilstanden ændrede sig på {device}.',
            'error.stale.title' => 'Telemetri mistet', 'error.stale.body' => 'Der blev ikke modtaget ny telemetri fra {device}.',
            'error.code.title' => 'Brænderfejl', 'error.code.body' => 'Enheden {device} rapporterede fejlkode {error}.',
            'error.default.title' => 'Brænderadvarsel', 'error.default.body' => 'Enheden {device} rapporterede en fejltilstand.',
            'heartbeat.title' => 'Heartbeat fra brænder', 'heartbeat.body' => 'Der er ikke rapporteret advarselsaktivitet fra {device} inden for de sidste 24 timer.',
            'suffix.temperature' => ' Temperatur {temp}°C.', 'suffix.lfs.healthy' => ' LittleFS er sund.', 'suffix.lfs.degraded' => ' LittleFS er forringet.',
        ],
        'is' => [
            'test.title' => 'Pruftilkynning', 'test.body' => 'Þetta er Viking Bio-pruftilkynning frá push-PWA.',
            'cleaning.title' => 'Vikuleg áminning um hreinsun', 'cleaning.body' => 'Tími er kominn á vikulega hreinsun á brennaranum.',
            'alert.default.title' => 'Viking Bio-viðvörun', 'alert.default.body' => 'Ný stöðuuppfærsla frá brennara barst.',
            'flame.on.title' => 'Kveikt var á brennara', 'flame.on.body' => 'Logi greindist á {device}.',
            'flame.off.title' => 'Slökkt var á brennara', 'flame.off.body' => 'Loginn hvarf á {device}.', 'flame.default.body' => 'Logastaða breyttist á {device}.',
            'error.stale.title' => 'Mæligögn töpuðust', 'error.stale.body' => 'Engin ný mæligögn bárust frá {device}.',
            'error.code.title' => 'Villa í brennara', 'error.code.body' => 'Tækið {device} tilkynnti villukóða {error}.',
            'error.default.title' => 'Viðvörun frá brennara', 'error.default.body' => 'Tækið {device} tilkynnti villuástand.',
            'heartbeat.title' => 'Heartbeat frá brennara', 'heartbeat.body' => 'Engin viðvörunarvirkni hefur verið tilkynnt frá {device} síðustu 24 klukkustundir.',
            'suffix.temperature' => ' Hiti {temp}°C.', 'suffix.lfs.healthy' => ' LittleFS er í lagi.', 'suffix.lfs.degraded' => ' LittleFS er skert.',
        ],
    ];

    public static function supportedLanguages(): array
    {
        return self::SUPPORTED_LANGUAGES;
    }

    public static function normaliseLanguage(?string $value): string
    {
        $candidate = strtolower(trim((string) $value));
        if ($candidate === '') {
            return self::DEFAULT_LANGUAGE;
        }

        $candidate = str_replace('_', '-', $candidate);

        return match (true) {
            str_starts_with($candidate, 'sv') => 'sv',
            str_starts_with($candidate, 'no'), str_starts_with($candidate, 'nb'), str_starts_with($candidate, 'nn') => 'no',
            str_starts_with($candidate, 'fi') => 'fi',
            str_starts_with($candidate, 'da') => 'da',
            str_starts_with($candidate, 'is') => 'is',
            default => 'en',
        };
    }

    /**
     * @return array{title:string,body:string}
     */
    public static function testNotification(string $language): array
    {
        return [
            'title' => self::message($language, 'test.title'),
            'body' => self::message($language, 'test.body'),
        ];
    }

    /**
     * @return array{title:string,body:string}
     */
    public static function cleaningReminder(string $language): array
    {
        return [
            'title' => self::message($language, 'cleaning.title'),
            'body' => self::message($language, 'cleaning.body'),
        ];
    }

    /**
     * @return array{title:string,body:string}
     */
    public static function webhookAlert(string $language, string $type, string $detail, string $device, int $errorCode, ?float $temperature, ?bool $lfsHealth): array
    {
        $key = 'alert.default';
        if ($type === 'flame') {
            $key = $detail === 'on' ? 'flame.on' : ($detail === 'off' ? 'flame.off' : 'alert.default');
        } elseif ($type === 'error') {
            if ($detail === 'stale') {
                $key = 'error.stale';
            } elseif ($errorCode > 0) {
                $key = 'error.code';
            } else {
                $key = 'error.default';
            }
        } elseif ($type === 'heartbeat') {
            $key = 'heartbeat';
        }

        $titleKey = $key . '.title';
        $bodyKey = $key . '.body';
        if (!isset(self::MESSAGES[self::normaliseLanguage($language)][$titleKey])) {
            $titleKey = 'alert.default.title';
        }
        if (!isset(self::MESSAGES[self::normaliseLanguage($language)][$bodyKey])) {
            $bodyKey = 'alert.default.body';
        }

        $body = self::message($language, $bodyKey, [
            'device' => $device,
            'error' => (string) $errorCode,
        ]);

        if ($temperature !== null && $type !== 'error') {
            $body .= self::message($language, 'suffix.temperature', ['temp' => number_format($temperature, 1, '.', '')]);
        }
        if ($type === 'heartbeat' && $lfsHealth !== null) {
            $body .= $lfsHealth ? self::message($language, 'suffix.lfs.healthy') : self::message($language, 'suffix.lfs.degraded');
        }

        return [
            'title' => self::message($language, $titleKey, ['device' => $device]),
            'body' => $body,
        ];
    }

    public static function message(string $language, string $key, array $replacements = []): string
    {
        $normalized = self::normaliseLanguage($language);
        $catalog = self::MESSAGES[$normalized] ?? self::MESSAGES[self::DEFAULT_LANGUAGE];
        $fallback = self::MESSAGES[self::DEFAULT_LANGUAGE][$key] ?? '';
        $template = $catalog[$key] ?? $fallback;

        return preg_replace_callback('/\{(\w+)\}/', static function (array $matches) use ($replacements): string {
            return (string) ($replacements[$matches[1]] ?? '');
        }, $template) ?? $template;
    }
}
