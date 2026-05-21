module.exports = {
  clearMocks: true,
  coverageDirectory: 'coverage',
  moduleDirectories: [
    'src',
    'node_modules',
  ],
  resetMocks: true,
  restoreMocks: true,
  testEnvironment: 'node',
  transform: {
    '^.+\\.(ts|tsx)$': [
      'ts-jest',
      {
        tsconfig: './tsconfig.json',
      },
    ],
  },
  transformIgnorePatterns: [
    `./node_modules/ethereum-cryptography/src/*.ts`,
  ],
  testTimeout: 120000,
  preset: 'ts-jest',
}