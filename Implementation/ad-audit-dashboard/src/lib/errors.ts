/**
 * Errors raised while loading or validating a scan result or dictionary.
 *
 * They live in their own module so that the validator and the loader can both
 * raise them without importing each other.
 */

/** Something was read but is not usable. */
export class DataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DataError';
  }
}

/**
 * Nothing was there to read.
 *
 * Distinct from DataError on purpose. A missing file sends the reader to run
 * a scan; a corrupt one sends them to investigate the file. Reporting the
 * wrong one sends them looking in the wrong place.
 */
export class MissingFileError extends DataError {
  constructor(message: string) {
    super(message);
    this.name = 'MissingFileError';
  }
}
